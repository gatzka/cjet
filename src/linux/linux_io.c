/*
 *The MIT License (MIT)
 *
 * Copyright (c) <2014> <Stephan Gatzka>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "cjet_io.h"
#include "compiler.h"
#include "generated/os_config.h"
#include "linux/io_loop.h"
#include "linux/linux_io.h"
#include "linux/peer_testing.h"
#include "list.h"
#include "log.h"
#include "parse.h"
#include "peer.h"
#include "state.h"

static int go_ahead = 1;
static int epoll_fd;

static int set_fd_non_blocking(int fd)
{
	int fd_flags;

	fd_flags = fcntl(fd, F_GETFL, 0);
	if (unlikely(fd_flags < 0)) {
		log_err("Could not get fd flags!\n");
		return -1;
	}
	fd_flags |= O_NONBLOCK;
	if (unlikely(fcntl(fd, F_SETFL, fd_flags) < 0)) {
		log_err("Could not set %s!\n", "O_NONBLOCK");
		return -1;
	}
	return 0;
}

static struct peer *setup_listen_socket(void)
{
	int listen_fd;
	struct sockaddr_in6 serveraddr;
	static const int reuse_on = 1;
	struct peer *peer;

	listen_fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (listen_fd < 0) {
		log_err("Could not create listen socket!\n");
		return NULL;
	}

	if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse_on,
			sizeof(reuse_on)) < 0) {
		log_err("Could not set %s!\n", "SO_REUSEADDR");
		goto so_reuse_failed;
	}

	if (set_fd_non_blocking(listen_fd) < 0) {
		goto nonblock_failed;
	}

	memset(&serveraddr, 0, sizeof(serveraddr));
	serveraddr.sin6_family = AF_INET6;
	serveraddr.sin6_port = htons(CONFIG_SERVER_PORT);
	serveraddr.sin6_addr = in6addr_any;
	if (bind(listen_fd, (struct sockaddr *)&serveraddr,
		sizeof(serveraddr)) < 0) {
		log_err("bind failed!\n");
		goto bind_failed;
	}

	if (listen(listen_fd, CONFIG_LISTEN_BACKLOG) < 0) {
		log_err("listen failed!\n");
		goto listen_failed;
	}

	peer = alloc_peer(listen_fd);
	if (peer == NULL) {
		goto alloc_peer_wait_failed;
	}

	return peer;

alloc_peer_wait_failed:
listen_failed:
bind_failed:
nonblock_failed:
so_reuse_failed:
	close(listen_fd);
	return NULL;
}

int add_io(struct peer *p)
{
	return add_epoll(p->io.fd, epoll_fd, p);
}

void remove_io(const struct peer *p)
{
	remove_epoll(p->io.fd, epoll_fd);
}

static int configure_keepalive(int fd)
{
	int opt = 12;
	if (setsockopt(fd, SOL_TCP, TCP_KEEPIDLE, &opt, sizeof(opt)) == -1) {
		log_err("error setting socket option %s\n", "TCP_KEEPIDLE");
		return -1;
	}

	opt = 3;
	if (setsockopt(fd, SOL_TCP, TCP_KEEPINTVL, &opt, sizeof(opt)) == -1) {
		log_err("error setting socket option %s\n", "TCP_KEEPINTVL");
		return -1;
	}

	opt = 2;
	if (setsockopt(fd, SOL_TCP, TCP_KEEPCNT, &opt, sizeof(opt)) == -1) {
		log_err("error setting socket option %s\n", "TCP_KEEPCNT");
		return -1;
	}

	opt = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt)) == -1) {
		log_err("error setting socket option %s\n", "SO_KEEPALIVE");
		return -1;
	}

	return 0;
}

static int handle_new_connection(int fd)
{
	static const int tcp_nodelay_on = 1;

	if ((set_fd_non_blocking(fd) < 0) ||
		(setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &tcp_nodelay_on,
			sizeof(tcp_nodelay_on)) < 0)) {
		log_err("Could not set socket to nonblocking!\n");
		close(fd);
		return -1;
	}

	if (configure_keepalive(fd) < 0) {
		log_err("Could not configure keepalive!\n");
		close(fd);
		return -1;
	}

	struct peer *peer = alloc_peer(fd);
	if (unlikely(peer == NULL)) {
		log_err("Could not allocate peer!\n");
		close(fd);
		return -1;
	}

	return 0;
}

static int accept_all(int listen_fd)
{
	while (1) {
		int peer_fd;
		peer_fd = accept(listen_fd, NULL, NULL);
		if (peer_fd == -1) {
			if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
				return 0;
			} else {
				return -1;
			}
		} else {
			if (unlikely(handle_new_connection(peer_fd) != 0)) {
				return -1;
			}
		}
	}
}

char *get_read_ptr(struct peer *p, unsigned int count)
{
	if (unlikely((ptrdiff_t)count > unread_space(p))) {
		log_err("peer asked for too much data: %u!\n", count);
		return 0;
	}
	while (1) {
		ssize_t read_length;
		if ((p->write_ptr - p->read_ptr) >= (ptrdiff_t)count) {
			char *read_ptr = p->read_ptr;
			p->read_ptr += count;
			return read_ptr;
		}

		read_length =
			READ(p->io.fd, p->write_ptr, (size_t)free_space(p));
		if (unlikely(read_length == 0)) {
			return (char *)IO_CLOSE;
		}
		if (read_length == -1) {
			if (unlikely((errno != EAGAIN) &&
				(errno != EWOULDBLOCK))) {
				log_err("unexpected %s error: %s!\n", "read",
					strerror(errno));
				return (char *)IO_ERROR;
			}
			return (char *)IO_WOULD_BLOCK;
		}
		p->write_ptr += read_length;
	}
	return (char *)IO_ERROR;
}

int send_buffer(struct peer *p)
{
	char *write_buffer_ptr = p->write_buffer;
	while (p->to_write != 0) {
		ssize_t written;
		written =
			SEND(p->io.fd, write_buffer_ptr, p->to_write, MSG_NOSIGNAL);
		if (unlikely(written == -1)) {
			if (unlikely((errno != EAGAIN) &&
				(errno != EWOULDBLOCK))) {
				log_err("unexpected write error: %s!", strerror(errno));
				return -1;
			}
			memmove(p->write_buffer, write_buffer_ptr, p->to_write);
			if (p->op != WRITE_MSG) {
				p->next_read_op = p->op;
				p->op = WRITE_MSG;
			}
			return IO_WOULD_BLOCK;
		}
		write_buffer_ptr += written;
		p->to_write -= written;
	}
	return 0;
}

int copy_msg_to_write_buffer(struct peer *p, const void *rendered,
			 uint32_t msg_len_be, size_t already_written)
{
	size_t to_write;
	uint32_t msg_len = ntohl(msg_len_be);
	size_t free_space_in_buf = CONFIG_MAX_WRITE_BUFFER_SIZE - p->to_write;
	size_t bytes_to_copy =  (sizeof(msg_len_be) + msg_len) - already_written;

	if (unlikely(bytes_to_copy > free_space_in_buf)) {
		log_err("not enough space left in write buffer! %zu bytes of %i left", free_space_in_buf, CONFIG_MAX_WRITE_BUFFER_SIZE);
		return -1;
	}

	char *write_buffer_ptr = p->write_buffer + p->to_write;
	if (already_written < sizeof(msg_len_be)) {
		char *msg_len_ptr = (char *)(&msg_len_be);
		msg_len_ptr += already_written;
		to_write = sizeof(msg_len_be) - already_written;
		memcpy(write_buffer_ptr, msg_len_ptr, to_write);
		write_buffer_ptr += to_write;
		already_written += to_write;
		p->to_write += to_write;
	}

	size_t msg_offset = already_written - sizeof(msg_len_be);
	const char *message_ptr = (const char *)rendered + msg_offset;
	to_write = msg_len - msg_offset;
	memcpy(write_buffer_ptr, message_ptr, to_write);
	p->to_write += to_write;

	return 0;
}

int send_message(struct peer *p, const char *rendered, size_t len)
{
	int ret;
	struct iovec iov[2];
	ssize_t sent;
	size_t written = 0;
	uint32_t message_length = htonl(len);

	if (unlikely(p->op == WRITE_MSG)) {
		/*
		 * There is already something in p->write_buffer, that hasn't
		 * been written yet because the socket had blocked. In this case
		 * just append the new message to p->write_buffer.
		 */
		ret = copy_msg_to_write_buffer(p, rendered, message_length, 0);
		if (unlikely(ret == -1)) {
			return ret;
		}

		/* Try to send. This is important because send_message might
		 * be called several times from within one event loop callback function.
		 * In this case the buffer might be filled until overflow.
		 */
		ret = send_buffer(p);
		/*
		 * write in send_buffer blocked. This is not an error, so
		 * change ret to 0 (no error). Writing the missing stuff is
		 * handled via epoll / handle_all_peer_operations.
		 */
		if (ret == IO_WOULD_BLOCK) {
			ret = 0;
		}
		return ret;
	}

	iov[0].iov_base = &message_length;
	iov[0].iov_len = sizeof(message_length);
/*
 * This pragma is used because iov_base is not declared const.
 * Nevertheless, I want to have the rendered paramter const. Therefore I
 * selectively disabled the cast-qual warning.
 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
	iov[1].iov_base = (void *)rendered;
#pragma GCC diagnostic pop
	iov[1].iov_len = len;

	sent = WRITEV(p->io.fd, iov, sizeof(iov) / sizeof(struct iovec));
	if (likely(sent == ((ssize_t)len + (ssize_t)sizeof(message_length)))) {
		return 0;
	}

	if (sent > 0) {
		written += (size_t)sent;
	}

	if (unlikely((sent == -1) &&
		((errno != EAGAIN) && (errno != EWOULDBLOCK)))) {
		log_err("unexpected %s error: %s!\n", "write",
			strerror(errno));
		return -1;
	}
	if (unlikely(copy_msg_to_write_buffer(p, rendered, message_length,
		written) == -1)) {
		return -1;
	}

	if (sent == -1) {
		/* the write call has blocked */
		p->next_read_op = p->op;
		p->op = WRITE_MSG;
		return 0;
	}

	/*
	 * The write call didn't block, but only wrote parts of the
	 * messages. Try to send the rest.
	 */
	ret = send_buffer(p);
	/*
	 * write in send_buffer blocked. This is not an error, so
	 * change ret to 0 (no error). Writing the missing stuff is
	 * handled via epoll / handle_all_peer_operations.
	 */
	if (ret == IO_WOULD_BLOCK) {
		ret = 0;
	}
	return ret;
}

static int read_msg_length(struct peer *p)
{
	uint32_t message_length;
	char *message_length_ptr =
		get_read_ptr(p, sizeof(message_length));
	intptr_t ret = (intptr_t)message_length_ptr;
	if (unlikely(ret <= 0)) {
		if (ret == IO_WOULD_BLOCK) {
			return 0;
		} else {
			return ret;
		}
	} else {
		memcpy(&message_length, message_length_ptr,
			sizeof(message_length));
		message_length = ntohl(message_length);
		p->op = READ_MSG;
		p->msg_length = message_length;
		return 1;
	}
}

static int read_msg(struct peer *p)
{
	uint32_t message_length = p->msg_length;
	char *message_ptr = get_read_ptr(p, message_length);
	intptr_t ret = (intptr_t)message_ptr;
	if (unlikely(ret <= 0)) {
		if (ret == IO_WOULD_BLOCK) {
			return 0;
		} else {
			return ret;
		}
	} else {
		p->op = READ_MSG_LENGTH;
		ret = parse_message(message_ptr, message_length, p);
		if (unlikely(ret == -1)) {
			return -1;
		}
		reorganize_read_buffer(p);
		return 1;
	}
}

static int write_msg(struct peer *p)
{
	int ret = send_buffer(p);
	if (likely(ret == 0)) {
		p->op = p->next_read_op;
		return 0;
	} else if (unlikely(ret == -1)) {
		return -1;
	}
	/*
	 * ret == IO_WOULD_BLOCK shows that send_buffer blocked.
	 * Leave everything like it is.
	 */
	 return 0;
}

int handle_all_peer_operations(struct peer *p)
{
	while (1) {
		int ret;

		switch (p->op) {
		case READ_MSG_LENGTH:
			ret = read_msg_length(p);
			if (unlikely(ret <= 0)) {
				return ret;
			}
			break;

		case READ_MSG:
			ret = read_msg(p);
			if (unlikely(ret <= 0)) {
				return ret;
			}
			break;

		case WRITE_MSG:
			ret = write_msg(p);
			if (ret < 0) {
				return ret;
			}
			break;

		default:
			log_err("Unknown client operation!\n");
			return -1;
			break;
		}
	}
	return -1;
}

static void sighandler(int signum)
{
	(void)signum;
	go_ahead = 0;
}

static int register_signal_handler(void)
{
	if (signal(SIGTERM, sighandler) == SIG_ERR) {
		log_err("signal failed!\n");
		return -1;
	}
	if (signal(SIGINT, sighandler) == SIG_ERR) {
		log_err("signal failed!\n");
		signal(SIGTERM, SIG_DFL);
		return -1;
	}
	return 0;
}

static void unregister_signal_handler(void)
{
	signal(SIGINT, SIG_DFL);
	signal(SIGTERM, SIG_DFL);
}

static int handle_error_events(struct peer *p,
	const struct peer *listen_server)
{
	if (p == listen_server) {
		log_err("epoll error on listen fd!\n");
		return -1;
	} else {
		log_warn("epoll error on peer fd!\n");
		free_peer(p);
		return 0;
	}
}

static int handle_normal_events(struct peer *p,
	const struct peer *listen_server)
{
	if (unlikely(p == listen_server)) {
		if (accept_all(listen_server->io.fd) < 0) {
			return -1;
		} else {
			return 0;
		}
	} else {
		int ret = handle_all_peer_operations(p);
		if (unlikely(ret == -1)) {
			free_peer(p);
		}
		return 0;
	}
}

static int handle_events(int num_events, struct epoll_event *events,
	struct peer *listen_server)
{
	if (unlikely(num_events == -1)) {
		if (errno == EINTR) {
			return 0;
		} else {
			return -1;
		}
	}
	for (int i = 0; i < num_events; ++i) {
		if (unlikely((events[i].events & EPOLLERR) ||
				(events[i].events & EPOLLHUP))) {
			if (handle_error_events(events[i].data.ptr, listen_server) != 0) {
				return -1;
			}
		} else {
			if (unlikely(handle_normal_events(events[i].data.ptr,
					listen_server) != 0)) {
				return -1;
			}
		}
	}
	return 0;
}

int run_io(void)
{
	int ret = 0;
	struct epoll_event events[CONFIG_MAX_EPOLL_EVENTS];

	if (register_signal_handler() < 0) {
		return -1;
	}
	epoll_fd = epoll_create(1);
	if (epoll_fd < 0) {
		go_ahead = 0;
		ret = -1;
	}

	struct peer *listen_server = setup_listen_socket();
	if (listen_server == NULL) {
		go_ahead = 0;
		ret = -1;
	}

	while (likely(go_ahead)) {
		int num_events =
		    epoll_wait(epoll_fd, events, CONFIG_MAX_EPOLL_EVENTS, -1);

		if (unlikely(handle_events(num_events, events, listen_server) != 0)) {
			ret = -1;
			break;
		}
	}

	destroy_all_peers();
	close(epoll_fd);
	unregister_signal_handler();
	return ret;
}
