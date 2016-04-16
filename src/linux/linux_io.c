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
#include <pwd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "cjet_io.h"
#include "compiler.h"
#include "generated/os_config.h"
#include "linux/io_event.h"
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

enum callback_return add_io(struct io_event *ev)
{
	struct epoll_event epoll_ev;

	memset(&epoll_ev, 0, sizeof(epoll_ev));
	epoll_ev.data.ptr = ev;
	epoll_ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
	if (unlikely(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ev->context.fd, &epoll_ev) < 0)) {
		log_err("epoll_ctl failed!\n");
		return ABORT_LOOP;
	}

	if (likely(ev->read_function != NULL)) {
		return ev->read_function(&ev->context);
	}
	return CONTINUE_LOOP;
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

static void handle_new_connection(int fd)
{
	static const int tcp_nodelay_on = 1;

	if ((set_fd_non_blocking(fd) < 0) ||
		(setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &tcp_nodelay_on,
			sizeof(tcp_nodelay_on)) < 0)) {
		log_err("Could not set socket to nonblocking!\n");
		close(fd);
		return;
	}

	if (configure_keepalive(fd) < 0) {
		log_err("Could not configure keepalive!\n");
		close(fd);
		return;
	}

	struct peer *peer = alloc_peer(fd);
	if (unlikely(peer == NULL)) {
		log_err("Could not allocate peer!\n");
		close(fd);
		return;
	}

	return;
}

static enum callback_return accept_all(union io_context *io)
{
	while (1) {
		int peer_fd;
		peer_fd = accept(io->fd, NULL, NULL);
		if (peer_fd == -1) {
			if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
				return CONTINUE_LOOP;
			} else {
				return ABORT_LOOP;
			}
		} else {
			handle_new_connection(peer_fd);
		}
	}
}

static int accept_error(union io_context *io)
{
	(void)io;
	return -1;
}

static struct server *alloc_server(int fd)
{
	struct server *s = malloc(sizeof(*s));
	if (unlikely(s == NULL)) {
		return NULL;
	}
	s->ev.context.fd = fd;
	s->ev.read_function = accept_all;
	s->ev.write_function = NULL;
	s->ev.error_function = accept_error;


	if (add_io(&s->ev) < 0) {
		free(s);
		return NULL;
	}

	return s;
}

static struct server *create_server(int server_port)
{
	int listen_fd;
	struct sockaddr_in6 serveraddr;
	static const int reuse_on = 1;

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
	serveraddr.sin6_port = htons(server_port);
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

	struct server *server = alloc_server(listen_fd);
	if (server == NULL) {
		goto alloc_server_wait_failed;
	}

	return server;

alloc_server_wait_failed:
listen_failed:
bind_failed:
nonblock_failed:
so_reuse_failed:
	close(listen_fd);
	return NULL;
}

static void delete_server(struct server *server)
{
	close(server->ev.context.fd);
	free(server);
}

void remove_io(const struct peer *p)
{
	epoll_ctl(epoll_fd, EPOLL_CTL_DEL, p->ev.context.fd, NULL);
	close(p->ev.context.fd);
}

ssize_t get_read_ptr(struct peer *p, unsigned int count, const char **read_ptr)
{
	if (unlikely((ptrdiff_t)count > unread_space(p))) {
		log_err("peer asked for too much data: %u!\n", count);
		*read_ptr = NULL;
		return IO_TOOMUCHDATA;
	}
	while (1) {
		ssize_t read_length;
		ptrdiff_t diff = p->write_ptr - p->read_ptr;
		if (diff >= (ptrdiff_t)count) {
			*read_ptr = p->read_ptr;
			p->read_ptr += count;
			return diff;
		}

		read_length = READ(p->ev.context.fd, p->write_ptr, (size_t)free_space(p));
		if (unlikely(read_length == 0)) {
			*read_ptr = NULL;
			return IO_CLOSE;
		}
		if (read_length == -1) {
			if (unlikely((errno != EAGAIN) && (errno != EWOULDBLOCK))) {
				log_err("unexpected %s error: %s!\n", "read", strerror(errno));
				*read_ptr = NULL;
				return IO_ERROR;
			}
			*read_ptr = NULL;
			return IO_WOULD_BLOCK;
		}
		p->write_ptr += read_length;
	}
	*read_ptr = NULL;
	return IO_ERROR;
}

int send_buffer(struct peer *p)
{
	char *write_buffer_ptr = p->write_buffer;
	while (p->to_write != 0) {
		ssize_t written;
		written =
			SEND(p->ev.context.fd, write_buffer_ptr, p->to_write, MSG_NOSIGNAL);
		if (unlikely(written == -1)) {
			if (unlikely((errno != EAGAIN) &&
				(errno != EWOULDBLOCK))) {
				log_err("unexpected write error: %s!", strerror(errno));
				return -1;
			}
			memmove(p->write_buffer, write_buffer_ptr, p->to_write);
			return 0;
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
	uint32_t msg_len = be32toh(msg_len_be);
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
	struct iovec iov[3];
	ssize_t sent;
	size_t written = 0;
	uint32_t message_length = htonl(len);

	iov[0].iov_base = p->write_buffer;
	iov[0].iov_len = p->to_write;

	iov[1].iov_base = &message_length;
	iov[1].iov_len = sizeof(message_length);
/*
 * This pragma is used because iov_base is not declared const.
 * Nevertheless, I want to have the rendered parameter const. Therefore I
 * selectively disabled the cast-qual warning.
 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
	iov[2].iov_base = (void *)rendered;
#pragma GCC diagnostic pop
	iov[2].iov_len = len;

	sent = WRITEV(p->ev.context.fd, iov, sizeof(iov) / sizeof(struct iovec));
	if (likely(sent == ((ssize_t)len + (ssize_t)sizeof(message_length)))) {
		return 0;
	}

	if (sent > 0) {
		written = (size_t)sent;
	}

	if (unlikely((sent == -1) &&
		((errno != EAGAIN) && (errno != EWOULDBLOCK)))) {
		log_err("unexpected %s error: %s!\n", "write",
			strerror(errno));
		return -1;
	}

	size_t already_written;
	if (written <= p->to_write) {
		p->to_write -= written;
		memmove(p->write_buffer, p->write_buffer + written, p->to_write);
		already_written = 0;
	} else {
		already_written = written;
		p->to_write = 0;
	}
	if (unlikely(copy_msg_to_write_buffer(p, rendered, message_length,
		already_written) == -1)) {
		return -1;
	}

	if (sent == -1) {
		/* the write call has blocked */
		return 0;
	}

	/*
	 * The write call didn't block, but only wrote parts of the
	 * messages. Try to send the rest.
	 */
	ret = send_buffer(p);
	return ret;
}

static int read_msg_length(struct peer *p)
{
	uint32_t message_length;
	const char *message_length_ptr;
	ssize_t ret = get_read_ptr(p, sizeof(message_length), &message_length_ptr);
	if (unlikely(ret <= 0)) {
		if (ret == IO_WOULD_BLOCK) {
			return 0;
		}
	} else {
		memcpy(&message_length, message_length_ptr, sizeof(message_length));
		p->op = READ_MSG;
		p->msg_length = ntohl(message_length);
	}
	return ret;
}

static int read_msg(struct peer *p)
{
	uint32_t message_length = p->msg_length;
	const char *message_ptr;
	ssize_t ret = get_read_ptr(p, message_length, &message_ptr);
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

enum callback_return write_msg(union io_context *context)
{
	struct peer *p = container_of(context, struct peer, ev);

	int ret = send_buffer(p);
	if (unlikely(ret < 0)) {
		free_peer(context);
	}
	 return CONTINUE_LOOP;
}

enum callback_return handle_all_peer_operations(union io_context *context)
{
	struct peer *p = container_of(context, struct peer, ev);
	while (1) {
		int ret;

		switch (p->op) {
		case READ_MSG_LENGTH:
			ret = read_msg_length(p);
			break;

		case READ_MSG:
			ret = read_msg(p);
			break;

		default:
			log_err("Unknown client operation!\n");
			ret = -1;
			break;
		}

		if (unlikely(ret <= 0)) {
			if (unlikely(ret < 0)) {
				free_peer(context);
			}
			return CONTINUE_LOOP;
		}
	}
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

static enum callback_return handle_events(int num_events, struct epoll_event *events)
{
	if (unlikely(num_events == -1)) {
		if (errno == EINTR) {
			return CONTINUE_LOOP;
		} else {
			return ABORT_LOOP;
		}
	}
	for (int i = 0; i < num_events; ++i) {
		struct io_event *ev = events[i].data.ptr;

		if (unlikely((events[i].events & EPOLLERR) ||
				(events[i].events & EPOLLHUP))) {
			if (ev->error_function(&ev->context) == ABORT_LOOP) {
				return ABORT_LOOP;
			}
		} else {
			if (events[i].events & EPOLLIN) {
				if (likely(ev->read_function != NULL)  && (ev->read_function(&ev->context) == ABORT_LOOP)) {
					return ABORT_LOOP;
				}
			} else if (events[i].events & EPOLLOUT) {
				if (likely(ev->write_function != NULL) && (ev->write_function(&ev->context) == ABORT_LOOP)) {
					return ABORT_LOOP;
				}
			} else {
				return ABORT_LOOP;
			}
		}
	}
	return CONTINUE_LOOP;
}

static int drop_privileges(const char *user_name)
{
	struct passwd *passwd = getpwnam(user_name);
	if (passwd == NULL) {
		log_err("user name \"%s\" not available!\n", user_name);
		return -1;
	}
	if (setgid(passwd->pw_gid) == -1) {
		log_err("Can't set process' gid to gid of \"%s\"!\n", user_name);
		return -1;
	}
	if (setuid(passwd->pw_uid) == -1) {
		log_err("Can't set process' uid to uid of \"%s\"!\n", user_name);
		return -1;
	}
	return 0;
}

int run_io(const char *user_name)
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

	struct server *jet_server = create_server(CONFIG_SERVER_PORT);
	if (jet_server == NULL) {
		go_ahead = 0;
		ret = -1;
	}

	if ((user_name != NULL) && drop_privileges(user_name) < 0) {
		go_ahead = 0;
		ret = -1;
	}

	while (likely(go_ahead)) {
		int num_events =
			epoll_wait(epoll_fd, events, CONFIG_MAX_EPOLL_EVENTS, -1);

		if (unlikely(handle_events(num_events, events) == ABORT_LOOP)) {
			ret = -1;
			break;
		}
	}

	destroy_all_peers();
	delete_server(jet_server);

	close(epoll_fd);
	unregister_signal_handler();
	return ret;
}
