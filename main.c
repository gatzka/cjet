#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "compiler.h"
#include "config.h"
#include "peer.h"

static int shall_close = 0;

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

static int add_epoll(int epoll_fd, int epoll_op, int fd, void *cookie)
{
	struct epoll_event ev;

	memset(&ev, 0, sizeof(ev));
	ev.data.ptr = cookie;
	ev.events = EPOLLIN | EPOLLET;
	if (unlikely(epoll_ctl(epoll_fd, epoll_op, fd, &ev) < 0)) {
		fprintf(stderr, "epoll_ctl failed!\n");
		return -1;
	}
	return 0;
}

static void *peer_create_wait(int fd, int epoll_fd)
{
	struct peer *peer;
	peer = alloc_peer(fd);
	if (unlikely(peer == NULL)) {
		fprintf(stderr, "Could not allocate peer!\n");
		goto alloc_peer_failed;
	}

	if (unlikely(add_epoll(epoll_fd, EPOLL_CTL_ADD, fd, peer) < 0)) {
		goto epollctl_failed;
	}
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

	peer = peer_create_wait(listen_fd, epoll_fd);
	if (peer == NULL) {
		goto peer_create_wait_failed;
	}

	return peer;

peer_create_wait_failed:
listen_failed:
bind_failed:
nonblock_failed:
so_reuse_failed:
	close(listen_fd);
	return NULL;
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

			if (unlikely(set_fd_non_blocking(peer_fd) < 0)) {
				goto nonblock_failed;
			}

			if (unlikely(setsockopt(peer_fd, IPPROTO_TCP, TCP_NODELAY, &tcp_nodelay_on, sizeof(tcp_nodelay_on)) < 0)) {
				goto no_delay_failed;
			}

			peer = peer_create_wait(peer_fd, epoll_fd);
			if (unlikely(peer == NULL)) {
				fprintf(stderr, "Could not allocate peer!\n");
				goto peer_create_wait_failed;
			}
			return 0;

peer_create_wait_failed:
no_delay_failed:
nonblock_failed:
			close(peer_fd);
			return -1;
		}
	}
}

static void sighandler(int signum)
{
	(void)signum;
	shall_close = 1;
}

int main()
{
	struct sigaction act;

	int epoll_fd;
	struct epoll_event events[MAX_EPOLL_EVENTS];
	struct peer *listen_server;

	memset(&act, 0, sizeof(act));
	act.sa_handler = sighandler;
	if (sigaction(SIGTERM, &act, NULL) < 0) {
		fprintf(stderr, "sigaction failed!\n");
		return EXIT_FAILURE;
	}

	if((epoll_fd = epoll_create(1)) < 0) {
		fprintf(stderr, "epoll_create failed!\n");
		return EXIT_FAILURE;
	}

	if ((listen_server = setup_listen_socket(epoll_fd)) == NULL)  {
		goto setup_listen_failed;
	}

	while (1) {
		int num_events;
		int i;

		if (unlikely(shall_close)) {
			break;
		}
		num_events = epoll_wait(epoll_fd, events, MAX_EPOLL_EVENTS, -1);
		if (unlikely(num_events == -1)) {
			if (errno == EINTR) {
				break;
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
					fprintf(stderr, "epoll error on peer fd!\n");
					peer_unwait_delete(events[i].data.ptr, epoll_fd);
					continue;
				}
			}
			if (unlikely(events[i].data.ptr == listen_server)) {
				if (accept_all(epoll_fd, listen_server->fd) < 0) {
					goto accept_peer_failed;
				}
			} else {
				struct peer *peer = events[i].data.ptr;
				handle_all_peer_operations(peer, epoll_fd);
			}
		}
	}
/*
 * I do not waste code to close all peer fds, because the will be
 * closed by the OS if this process ends.
 */

	peer_unwait_delete(listen_server, epoll_fd);
	close(epoll_fd);
	return EXIT_SUCCESS;

epoll_wait_failed:
accept_peer_failed:
epoll_on_listen_failed:
/*
 * I do not waste code to close all peer fds, because the will be
 * closed by the OS if this process ends.
 */
	peer_unwait_delete(listen_server, epoll_fd);
setup_listen_failed:
	close(epoll_fd);
	return EXIT_FAILURE;
}
