#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "../compiler.h"
#include "../peer.h"
#include "io.h"

static inline void *create_peer(int fd)
{
	return alloc_peer(fd);
}

static void destroy_peer(struct peer *p, int fd)
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

	peer = create_peer(listen_fd);
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
		destroy_peer(peer, peer->io.fd);
	}
	return NULL;
}

int run_io_mt(volatile int *shall_close)
{
	struct peer *listen_server;
	int listen_fd;

	if ((listen_server = setup_listen_socket()) == NULL)  {
		return -1;
	}
	listen_fd = listen_server->io.fd;

	while (1) {
		int peer_fd;
		if (unlikely(*shall_close)) {
			break;
		}
		peer_fd = accept(listen_fd, NULL, NULL);
		if (peer_fd == -1) {
			if (errno == EINTR) {
				continue;
			} else {
				goto accept_failed;
			}
		} else {
			struct peer *peer;
			pthread_t thread_id;
			pthread_attr_t attr;
			static const int tcp_nodelay_on = 1;

			if (unlikely(setsockopt(peer_fd, IPPROTO_TCP, TCP_NODELAY, &tcp_nodelay_on, sizeof(tcp_nodelay_on)) < 0)) {
				goto no_delay_failed;
			}

			peer = create_peer(peer_fd);
			if (unlikely(peer == NULL)) {
				fprintf(stderr, "Could not allocate peer!\n");
				goto alloc_peer_failed;
			}

			if (pthread_attr_init(&attr) != 0) {
				fprintf(stderr, "could set init thread attribute!\n");
				goto pthread_attr_init_failed;
			}
			if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED) != 0) {
				fprintf(stderr, "could set detach attribute for peer thread!\n");
				goto pthread_setdetach_failed;
			}
			if (pthread_create(&thread_id, NULL, handle_client, peer) != 0) {
				fprintf(stderr, "could not create thread for peer!\n");
				goto pthread_create_failed;
			}
			continue;

		pthread_create_failed:
		pthread_setdetach_failed:
		pthread_attr_init_failed:
		alloc_peer_failed:
		no_delay_failed:
			close(peer_fd);
		accept_failed:
			destroy_peer(listen_server, listen_server->io.fd);
			return -1;
		}
	}
	destroy_peer(listen_server, listen_server->io.fd);
	return 0;
}

