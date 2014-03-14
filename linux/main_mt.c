#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "../compiler.h"
#include "../peer.h"
#include "../state.h"
#include "config.h"

static int shall_close = 0;

static void close_peer_connection(struct peer *p, int fd)
{
	close(fd);
	free_peer(p);
}

static struct peer *setup_listen_socket()
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

	peer = alloc_peer(listen_fd);
	if (peer == NULL) {
		goto alloc_peer_failed;
	}

	return peer;

alloc_peer_failed:
listen_failed:
bind_failed:
so_reuse_failed:
	close(listen_fd);
	return NULL;
}

static void *handle_client(void *arg)
{
	struct peer *peer = arg;

	int ret = handle_all_peer_operations(peer);
	if (unlikely(ret == -1)) {
		close_peer_connection(peer, peer->fd);
	}
	return NULL;
}

static int accept_all(int listen_fd)
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
			pthread_t thread_id;
			static const int tcp_nodelay_on = 1;

			if (unlikely(setsockopt(peer_fd, IPPROTO_TCP, TCP_NODELAY, &tcp_nodelay_on, sizeof(tcp_nodelay_on)) < 0)) {
				goto no_delay_failed;
			}

			peer = alloc_peer(peer_fd);
			if (unlikely(peer == NULL)) {
				fprintf(stderr, "Could not allocate peer!\n");
				goto alloc_peer_failed;
			}

			if (pthread_create(&thread_id, NULL, handle_client, peer) != 0) {
				fprintf(stderr, "could not create thread for peer!\n");
				goto pthread_create_failed;
			}
			return 0;

		pthread_create_failed:
		alloc_peer_failed:
		no_delay_failed:
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
	struct peer *listen_server;

	if (signal(SIGTERM, sighandler) == SIG_ERR) {
		fprintf(stderr, "signal failed!\n");
		return EXIT_FAILURE;
	}

	if ((create_setter_hashtable()) == -1) {
		fprintf(stderr, "Cannot allocate hashtable for states!\n");
		goto create_setter_hashtable_failed;
	}

	if ((listen_server = setup_listen_socket()) == NULL)  {
		goto setup_listen_failed;
	}

	while (1) {

		if (unlikely(shall_close)) {
			break;
		}
		if (accept_all(listen_server->fd) < 0) {
			goto accept_peer_failed;
		}
	}
/*
 * I do not waste code to close all peer fds, because they will be
 * closed by the OS if this process ends.
 */

	close_peer_connection(listen_server, listen_server->fd);
	delete_setter_hashtable();
	return EXIT_SUCCESS;

accept_peer_failed:
/*
 * I do not waste code to close all peer fds, because the will be
 * closed by the OS if this process ends.
 */
	close_peer_connection(listen_server, listen_server->fd);
setup_listen_failed:
	delete_setter_hashtable();
create_setter_hashtable_failed:
	return EXIT_FAILURE;
}
