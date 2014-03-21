#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "compiler.h"
#include "io.h"
#include "list.h"
#include "parse.h"
#include "peer.h"
#include "peer_io.h"
#include "peer_io_ops.h"
#include "peer_testing.h"
#include "state.h"

static LIST_HEAD(peer_list);
static int go_ahead = 1;
static int number_of_peers = 0;

static int set_fd_non_blocking(int fd)
{
	int fd_flags;

	if (unlikely((fd_flags = fcntl(fd, F_GETFL, 0)) < 0)) {
		fprintf(stderr, "Could not get fd flags!\n");
		return -1;
	}
	fd_flags |= O_NONBLOCK;
	if (unlikely(fcntl(fd, F_SETFL, fd_flags) < 0)) {
		fprintf(stderr, "Could not set O_NONBLOCK!\n");
		return -1;
	}
	return 0;
}

static int add_epoll(int epoll_fd, int fd, void *cookie)
{
	struct epoll_event ev;

	memset(&ev, 0, sizeof(ev));
	ev.data.ptr = cookie;
	ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
	if (unlikely(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0)) {
		fprintf(stderr, "epoll_ctl failed!\n");
		return -1;
	}
	return 0;
}

static void *create_peer(int fd, int epoll_fd)
{
	struct peer *peer;
	peer = alloc_peer(fd);
	if (unlikely(peer == NULL)) {
		fprintf(stderr, "Could not allocate peer!\n");
		goto alloc_peer_failed;
	}

	if (unlikely(add_epoll(epoll_fd, fd, peer) < 0)) {
		goto epollctl_failed;
	}
	list_add_tail(&peer->io.list, &peer_list);
	return peer;

epollctl_failed:
	free_peer(peer);
alloc_peer_failed:
	return NULL;
}

static struct peer *setup_listen_socket(int epoll_fd)
{
	int listen_fd;
	struct sockaddr_in6 serveraddr;
	static const int reuse_on = 1;
	struct peer *peer;

	if ((listen_fd = socket(AF_INET6, SOCK_STREAM, 0)) < 0) {
		fprintf(stderr, "Could not create listen socket!\n");
		return NULL;
	}

	if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse_on, sizeof(reuse_on)) < 0) {
		fprintf(stderr, "Could not set SO_REUSEADDR!\n");
		goto so_reuse_failed;
	}

	if (set_fd_non_blocking(listen_fd) < 0) {
		goto nonblock_failed;
	}

	memset(&serveraddr, 0, sizeof(serveraddr));
	serveraddr.sin6_family = AF_INET6;
	serveraddr.sin6_port = htons(SERVER_PORT);
	serveraddr.sin6_addr = in6addr_any;
	if (bind(listen_fd, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0) {
		fprintf(stderr, "bind failed!\n");
		goto bind_failed;
	}

	if (listen(listen_fd, LISTEN_BACKLOG) < 0) {
		fprintf(stderr, "listen failed!\n");
		goto listen_failed;
	}

	peer = create_peer(listen_fd, epoll_fd);
	if (peer == NULL) {
		goto create_peer_wait_failed;
	}

	return peer;

create_peer_wait_failed:
listen_failed:
bind_failed:
nonblock_failed:
so_reuse_failed:
	close(listen_fd);
	return NULL;
}

static void destroy_peer(struct peer *p, int epoll_fd, int fd)
{
	remove_all_states_from_peer(p);
	list_del(&p->io.list);
	epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL);
	close(fd);
	free_peer(p);
	number_of_peers--;
}

static void destroy_all_peers(int epoll_fd)
{
	struct list_head *item;
	struct list_head *tmp;
	list_for_each_safe(item, tmp, &peer_list) {
		struct peer *p = list_entry(item, struct io, list);
		destroy_peer(p, epoll_fd, p->io.fd);
	}
}

static int accept_all(int epoll_fd, int listen_fd)
{
	while (1) {
		int peer_fd;
		peer_fd = accept(listen_fd, NULL, NULL);
		if (peer_fd == -1) {
			if ((errno == EAGAIN) ||
			    (errno == EWOULDBLOCK)) {
				return 0;
			} else {
				return -1;
			}
		} else {
			struct peer *peer;
			static const int tcp_nodelay_on = 1;

			if (unlikely(number_of_peers >= MAX_NUMBER_OF_PEERS)) {
				close(peer_fd);
				continue;
			}

			if (unlikely(set_fd_non_blocking(peer_fd) < 0)) {
				goto nonblock_failed;
			}

			if (unlikely(setsockopt(peer_fd, IPPROTO_TCP, TCP_NODELAY, &tcp_nodelay_on, sizeof(tcp_nodelay_on)) < 0)) {
				goto no_delay_failed;
			}

			peer = create_peer(peer_fd, epoll_fd);
			if (unlikely(peer == NULL)) {
				fprintf(stderr, "Could not allocate peer!\n");
				goto create_peer_wait_failed;
			}
			number_of_peers++;
			continue;

		create_peer_wait_failed:
		no_delay_failed:
		nonblock_failed:
			close(peer_fd);
			return -1;
		}
	}
}

char *get_read_ptr(struct peer *p, unsigned int count)
{
	if (unlikely((ptrdiff_t)count > unread_space(p))) {
		fprintf(stderr, "peer asked for too much data: %d!\n", count);
		return NULL;
	}
	while (1) {
		ssize_t read_length;
		if (p->write_ptr - p->read_ptr >= (ptrdiff_t)count) {
			char *read_ptr = p->read_ptr;
			p->read_ptr += count;
			return read_ptr;
		}

		read_length = READ(p->io.fd, p->write_ptr, (size_t)free_space(p));
		if (unlikely(read_length == 0)) {
			/* peer closed connection */
			return NULL;
		}
		if (read_length == -1) {
			if (unlikely((errno != EAGAIN) &&
			             (errno != EWOULDBLOCK))) {
				fprintf(stderr, "unexpected read error: %s!\n", strerror(errno));
				return NULL;
			}
			return (char *)IO_WOULD_BLOCK;
		}
		p->write_ptr += read_length;
	}
}

static void sighandler(int signum)
{
	(void)signum;
	go_ahead = 0;
}

int send_buffer(struct peer *p)
{
	char *write_buffer_ptr = p->write_buffer;
	while (p->to_write != 0) {
		ssize_t written;
		written = SEND(p->io.fd, write_buffer_ptr, p->to_write, MSG_NOSIGNAL);
		if (unlikely(written == -1)) {
			if (unlikely((errno != EAGAIN) &&
			             (errno != EWOULDBLOCK))) {
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

int send_message(struct peer *p, char *rendered, size_t len)
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
		 return ret;
	}

	iov[0].iov_base = &message_length;
	iov[0].iov_len = sizeof(message_length);
	iov[1].iov_base = rendered;
	iov[1].iov_len = len;

	sent = WRITEV(p->io.fd, iov, sizeof(iov) / sizeof(struct iovec));
	if (likely(sent == ((ssize_t)len + (ssize_t)sizeof(message_length)))) {
		return 0;
	}

	if (sent > 0) {
		written += (size_t)sent;
	}

	if (unlikely((sent == -1) &&
	             ((errno != EAGAIN) &&
	              (errno != EWOULDBLOCK)))) {
		fprintf(stderr, "unexpected write error: %s!\n", strerror(errno));
		return -1;
	}
	if (unlikely(copy_msg_to_write_buffer(p, rendered, message_length, written) == -1)) {
		return -1;
	}

	if (sent == -1) {
		/* the writ call has blocked */
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

int handle_all_peer_operations(struct peer *p)
{
	uint32_t message_length;
	char *message_ptr;

	while (1) {
		char *message_length_ptr;
		int ret;

		switch (p->op) {
		case READ_MSG_LENGTH:
			message_length_ptr = get_read_ptr(p, sizeof(message_length));
			if (unlikely(message_length_ptr == NULL)) {
				return -1;
			} else if (message_length_ptr == (char *)IO_WOULD_BLOCK) {
				return 0;
			}
			memcpy(&message_length, message_length_ptr, sizeof(message_length));
			message_length = ntohl(message_length);
			p->op = READ_MSG;
			p->msg_length = message_length;
			/*
			 *  CAUTION! This fall through is by design! Typically, the
			 *  length of a messages and the message itself will go into
			 *  a single TCP packet. This fall through eliminates an
			 *  additional loop iteration.
			 */

		case READ_MSG:
			message_length = p->msg_length;
			message_ptr = get_read_ptr(p, message_length);
			if (unlikely(message_ptr == NULL)) {
				return -1;
			} else if (message_ptr == (char *)IO_WOULD_BLOCK) {
				return 0;
			}
			p->op = READ_MSG_LENGTH;
			ret = parse_message(message_ptr, message_length, p);
			if (unlikely(ret == -1)) {
				return -1;
			}
			reorganize_read_buffer(p);
			break;

		case WRITE_MSG:
			ret = send_buffer(p);
			if (unlikely(ret == -1)) {
				return -1;
			}
			if (likely(ret == 0)) {
				p->op = p->next_read_op;
			}
			/*
			 * ret == IO_WOULD_BLOCK shows that send_buffer blocked. Leave
			 * everything like it is.
			 */
			break;

		default:
			fprintf(stderr, "Unknown client operation!\n");
			return -1;
		}
	}
}

int run_io(void) {
	int epoll_fd;
	struct epoll_event events[MAX_EPOLL_EVENTS];
	struct peer *listen_server;

	if (signal(SIGTERM, sighandler) == SIG_ERR) {
		fprintf(stderr, "signal failed!\n");
		return -1;
	}
	if (signal(SIGINT, sighandler) == SIG_ERR) {
		fprintf(stderr, "signal failed!\n");
		goto signal_failed;
	}

	if ((epoll_fd = epoll_create(1)) < 0) {
		fprintf(stderr, "epoll_create failed!\n");
		goto epoll_create_failed;
	}

	if ((listen_server = setup_listen_socket(epoll_fd)) == NULL)  {
		goto setup_listen_failed;
	}

	while (likely(go_ahead)) {
		int num_events;
		int i;

		num_events = epoll_wait(epoll_fd, events, MAX_EPOLL_EVENTS, -1);
		if (unlikely(num_events == -1)) {
			if (errno == EINTR) {
				continue;
			} else {
				goto epoll_wait_failed;
			}
		}
		for (i = 0; i < num_events; i++) {
			if (unlikely((events[i].events & EPOLLERR) ||
			             (events[i].events & EPOLLHUP))) {
				if (events[i].data.ptr == listen_server) {
					fprintf(stderr, "epoll error on listen fd!\n");
					goto epoll_on_listen_failed;
				} else {
					struct peer *peer = events[i].data.ptr;
					fprintf(stderr, "epoll error on peer fd!\n");
					destroy_peer(peer, epoll_fd, peer->io.fd);
					continue;
				}
			}
			if (unlikely(events[i].data.ptr == listen_server)) {
				if (accept_all(epoll_fd, listen_server->io.fd) < 0) {
					goto accept_peer_failed;
				}
			} else {
				struct peer *peer = events[i].data.ptr;
				int ret = handle_all_peer_operations(peer);
				if (unlikely(ret == -1)) {
					destroy_peer(peer, epoll_fd, peer->io.fd);
				}
			}
		}
	}

	destroy_all_peers(epoll_fd);
	close(epoll_fd);
	return 0;

accept_peer_failed:
epoll_on_listen_failed:
epoll_wait_failed:
	destroy_peer(listen_server, epoll_fd, listen_server->io.fd);
setup_listen_failed:
	close(epoll_fd);
epoll_create_failed:
	signal(SIGINT, SIG_DFL);
signal_failed:
	signal(SIGTERM, SIG_DFL);
	return -1;
}

