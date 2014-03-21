#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "compiler.h"
#include "io.h"
#include "list.h"
#include "parse.h"
#include "peer.h"
#include "peer_io_ops.h"
#include "state.h"

#define IO_INTERRUPTED -2

static pthread_mutex_t num_peers_mtx = PTHREAD_MUTEX_INITIALIZER;
static int num_peers = 0;

static int get_number_of_peers(void)
{
	int peers;
	pthread_mutex_lock(&num_peers_mtx);
	peers = num_peers;
	pthread_mutex_unlock(&num_peers_mtx);
	return peers;
}

static void increment_number_of_peers(void)
{
	pthread_mutex_lock(&num_peers_mtx);
	num_peers++;
	pthread_mutex_unlock(&num_peers_mtx);
}

static void decrement_number_of_peers(void)
{
	pthread_mutex_lock(&num_peers_mtx);
	num_peers--;
	pthread_mutex_unlock(&num_peers_mtx);
}

static int go_ahead = 1;

static LIST_HEAD(peer_list);

static inline void *create_peer(int fd)
{
	struct peer *peer = alloc_peer(fd);
	if (unlikely(peer == NULL)) {
		fprintf(stderr, "Could not allocate peer!\n");
		return NULL;
	}
	list_add_tail(&peer->io.list, &peer_list);
	return peer;
}

static void wait_for_death(struct peer *p)
{
	pthread_mutex_lock(&p->io.death_mutex);
	while (!p->io.is_dead) {
		pthread_cond_wait(&p->io.death_cv, &p->io.death_mutex);
	}
	pthread_mutex_unlock(&p->io.death_mutex);
}

static void signal_peer_death(struct peer *p)
{
	pthread_mutex_lock(&p->io.death_mutex);
	p->io.is_dead = 1;
	pthread_cond_signal(&p->io.death_cv);
	pthread_mutex_unlock(&p->io.death_mutex);
}

static void shutdown_peer(struct peer *p, int fd)
{
	remove_all_states_from_peer(p);
	close(fd);
	signal_peer_death(p);
}

static void destroy_peer(struct peer *p)
{
	list_del(&p->io.list);
	free_peer(p);
	decrement_number_of_peers();
}

static void scan_for_dead_peers(void)
{
	struct list_head *item;
	struct list_head *tmp;
	list_for_each_safe(item, tmp, &peer_list) {
		struct peer *p = list_entry(item, struct io, list);
		pthread_t thread_id = p->io.thread_id;

		pthread_mutex_lock(&p->io.death_mutex);
		if (p->io.is_dead) {
			pthread_join(thread_id, NULL);
			destroy_peer(p);
		};
		pthread_mutex_unlock(&p->io.death_mutex);
	}
}

static void destroy_all_peers(void)
{
	struct list_head *item;
	struct list_head *tmp;
	list_for_each_safe(item, tmp, &peer_list) {
		struct peer *p = list_entry(item, struct io, list);
		pthread_t thread_id = p->io.thread_id;
		pthread_kill(thread_id, SIGUSR1);
		wait_for_death(p);
		pthread_join(thread_id, NULL);
		destroy_peer(p);
	}
}

static void sigusr1_handler()
{
}

static char *get_read_ptr(struct peer *p, unsigned int count)
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

		read_length = read(p->io.fd, p->write_ptr, (size_t)free_space(p));
		if (unlikely(read_length == 0)) {
			/* peer closed connection */
			return NULL;
		}
		if (read_length == -1) {
			if (unlikely(errno != EINTR)) {
				fprintf(stderr, "unexpected read error: %s!\n", strerror(errno));
				return NULL;
			}
			return (char *)IO_INTERRUPTED;
		}
		p->write_ptr += read_length;
	}
}

static int send_buffer(struct peer *p)
{
	char *write_buffer_ptr = p->write_buffer;
	while (p->to_write != 0) {
		ssize_t written;
		written = send(p->io.fd, write_buffer_ptr, p->to_write, MSG_NOSIGNAL);
		if (unlikely(written == -1)) {
			if (unlikely(errno != EINTR)) {
				return -1;
			}
			memmove(p->write_buffer, write_buffer_ptr, p->to_write);
			return IO_INTERRUPTED;
		}
		write_buffer_ptr += written;
		p->to_write -= written;
	}
	return 0;
}

int send_message(struct peer *p, char *rendered, size_t len)
{
	struct iovec iov[2];
	ssize_t sent;
	size_t written = 0;
	uint32_t message_length = htonl(len);

	if (unlikely(p->op == WRITE_MSG)) {
		/* 
		 * There is already something in p->write_buffer, that hasn't
		 * been written yet because the socket was interrupted. In this case
		 * just append the new message to p->write_buffer.
		 */
		 return copy_msg_to_write_buffer(p, rendered, message_length, 0);
	}

	iov[0].iov_base = &message_length;
	iov[0].iov_len = sizeof(message_length);
	iov[1].iov_base = rendered;
	iov[1].iov_len = len;

	sent = writev(p->io.fd, iov, sizeof(iov) / sizeof(struct iovec));
	if (likely(sent == ((ssize_t)len + (ssize_t)sizeof(message_length)))) {
		return 0;
	}

	if (sent >= 0) {
		written += (size_t)sent;
	}

	if (unlikely((sent == -1) &&
	             ((errno != EINTR)))) {
		fprintf(stderr, "unexpected write error: %s!\n", strerror(errno));
		return -1;
	}
	if (unlikely(copy_msg_to_write_buffer(p, rendered, message_length, written) == -1)) {
		return -1;
	}

	p->next_read_op = p->op;
	p->op = WRITE_MSG;
	if (sent == -1) {
		/* the write call was interrupted */
		return IO_INTERRUPTED;
	} else {
		/* only parts had been written */
		return 0;
	}
}

static int handle_all_peer_operations(struct peer *p)
{
	uint32_t message_length;
	char *message_ptr;

	char *message_length_ptr;
	int ret;

	switch (p->op) {
	case READ_MSG_LENGTH:
		message_length_ptr = get_read_ptr(p, sizeof(message_length));
		if (unlikely(message_length_ptr == NULL)) {
			return -1;
		} else if (unlikely(message_length_ptr == (char *)IO_INTERRUPTED)) {
			return IO_INTERRUPTED;
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
		} else if (message_ptr == (char *)IO_INTERRUPTED) {
			return IO_INTERRUPTED;
		}
		p->op = READ_MSG_LENGTH;
		ret = parse_message(message_ptr, message_length, p);
		reorganize_read_buffer(p);
		return ret;

	case WRITE_MSG:
		ret = send_buffer(p);
		if (likely(ret == 0)) {
			p->op = p->next_read_op;
		}
		return ret;

	default:
		fprintf(stderr, "Unknown client operation!\n");
		return -1;
	}
}

static void *handle_client(void *arg)
{
	struct peer *peer = arg;
	while (likely(go_ahead)) {
		int ret = handle_all_peer_operations(peer);
		if (ret == -1) {
			/*
			 * An error occured or the client closed the connection.
			 */
			break;
		}
	}
	fprintf(stdout, "closing peer!\n");
	shutdown_peer(peer, peer->io.fd);
	fprintf(stdout, "peer closed!\n");

	return NULL;
}

static int get_listen_socket()
{
	int listen_fd;
	struct sockaddr_in6 serveraddr;
	static const int reuse_on = 1;

	if ((listen_fd = socket(AF_INET6, SOCK_STREAM, 0)) < 0) {
		fprintf(stderr, "Could not create listen socket!\n");
		return -1;
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

	return listen_fd;

listen_failed:
bind_failed:
so_reuse_failed:
	close(listen_fd);
	return -1;
}

static void *handle_accept()
{
	int listen_fd = get_listen_socket();
	fprintf(stdout, "in accept thread!\n");

	while (likely(go_ahead)) {
		scan_for_dead_peers();
		int peer_fd = accept(listen_fd, NULL, NULL);
		if (unlikely(peer_fd == -1)) {
			if (errno == EINTR) {
				fprintf(stdout, "accept interrupted\n");
				continue;
			} else {
				fprintf(stderr, "Accept failed!\n");
				goto accept_failed;
			}
		} else {
			struct peer *peer;
			pthread_t thread_id;
			pthread_attr_t attr;
			static const int tcp_nodelay_on = 1;

			if (unlikely(get_number_of_peers() >= MAX_NUMBER_OF_PEERS)) {
				close(peer_fd);
				continue;
			}

			if (unlikely(setsockopt(peer_fd, IPPROTO_TCP, TCP_NODELAY, &tcp_nodelay_on, sizeof(tcp_nodelay_on)) < 0)) {
				goto no_delay_failed;
			}

			peer = create_peer(peer_fd);
			if (unlikely(peer == NULL)) {
				fprintf(stderr, "Could not allocate peer!\n");
				goto create_peer_failed;
			}
			peer->io.is_dead = 0;
			if (pthread_mutex_init(&peer->io.death_mutex, NULL) != 0) {
				fprintf(stderr, "Could not init mutex!\n");
				goto pthread_mutex_init_failed;
			}
			if (pthread_cond_init(&peer->io.death_cv, NULL) != 0) {
				fprintf(stderr, "Could not init condition variable!\n");
				goto pthread_cond_init_failed;
			}

			if (pthread_attr_init(&attr) != 0) {
				fprintf(stderr, "could set init thread attribute!\n");
				goto pthread_attr_init_failed;
			}
			if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE) != 0) {
				fprintf(stderr, "could set detach attribute for peer thread!\n");
				goto pthread_setdetach_failed;
			}
			if (pthread_create(&thread_id, NULL, handle_client, peer) != 0) {
				fprintf(stderr, "could not create thread for peer!\n");
				goto pthread_create_failed;
			}
			peer->io.thread_id = thread_id;
			increment_number_of_peers();

			continue;

		pthread_create_failed:
		pthread_setdetach_failed:
		pthread_attr_init_failed:
		pthread_cond_init_failed:
		pthread_mutex_init_failed:
			shutdown_peer(peer, peer_fd);
			destroy_peer(peer);
		create_peer_failed:
		no_delay_failed:
			close(peer_fd);
		accept_failed:
			fprintf(stdout, "accept finish unexpectedly!\n");
			close(listen_fd);
			return (void *)-1;
		}
	}

	fprintf(stdout, "accept finish!\n");
	close(listen_fd);
	return NULL;
}

static int kill_listen_thread(pthread_t listen_thread) {
	if (pthread_kill(listen_thread, SIGUSR1) != 0) {
		fprintf(stderr, "could not send kill to listen thread!\n");
		return -1;
	}
	fprintf(stdout, "killed listen thread!\n");
	if (pthread_join(listen_thread, NULL) != 0) {
		fprintf(stderr, "Could not join listen thread!\n");
		return -1;
	}
	fprintf(stdout, "joined listen thread!\n");
	return 0;
}

int run_io(void)
{
	sigset_t set;
	sigset_t old_set;
	struct sigaction sa;
	pthread_attr_t attr;
	pthread_t listen_thread;
	int sig;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sigusr1_handler;
	if (sigemptyset(&sa.sa_mask) != 0) {
		return -1;
	}
	if (sigaction(SIGUSR1, &sa, NULL) != 0) {
		return -1;
	}
	if (sigemptyset(&set) != 0) {
		return -1;
	}
	if (sigaddset(&set, SIGTERM) != 0) {
		return -1;
	}
	if (sigaddset(&set, SIGINT) != 0) {
		return -1;
	}
	if (pthread_sigmask(SIG_BLOCK, &set, &old_set) != 0) {
		return -1;
	}

	if (pthread_attr_init(&attr) != 0) {
		fprintf(stderr, "could set init thread attribute!\n");
		return -1;
	}
	if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE) != 0) {
		fprintf(stderr, "could set detach attribute for peer thread!\n");
		return -1;
	}
	if (pthread_create(&listen_thread, NULL, handle_accept, NULL) != 0) {
		fprintf(stderr, "could not create thread for peer!\n");
		return -1;
	}

	if (sigwait(&set, &sig) != 0) {
		return -1;
	}
	fprintf(stdout, "stopping everything!\n");
	go_ahead = 0;

	if (kill_listen_thread(listen_thread) != 0) {
		return -1;
	}
	fprintf(stdout, "destroy peers!\n");
	destroy_all_peers();
	return 0;
}

