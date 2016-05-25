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

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pwd.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "compiler.h"
#include "jet_endian.h"
#include "eventloop.h"
#include "http_connection.h"
#include "http_server.h"
#include "jet_server.h"
#include "linux/eventloop_epoll.h"
#include "linux/linux_io.h"
#include "linux/peer_testing.h"
#include "log.h"
#include "parse.h"
#include "peer.h"
#include "socket_peer.h"
#include "util.h"
#include "websocket_peer.h"

struct server {
	struct io_event ev;
};

static int go_ahead = 1;

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

static int prepare_peer_socket(int fd)
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
	return 0;
}

static void handle_new_jet_connection(const struct eventloop *loop, int fd)
{
	if (prepare_peer_socket(fd) < 0) {
		return;
	}

	struct socket_peer *peer = alloc_jet_peer(loop, fd);
	if (unlikely(peer == NULL)) {
		log_err("Could not allocate jet peer!\n");
		close(fd);
	}
}

static void handle_http(const struct eventloop *loop ,int fd)
{
	if (prepare_peer_socket(fd) < 0) {
		return;
	}
	struct http_connection *connection = alloc_http_connection(loop, fd);
	if (unlikely(connection == NULL)) {
		log_err("Could not allocate http connection!\n");
		close(fd);
	}
}

static enum callback_return accept_common(const struct eventloop *loop, union io_context *io,  void (*peer_function)(const struct eventloop*, int fd))
{
	while (1) {
		int peer_fd = accept(io->fd, NULL, NULL);
		if (peer_fd == -1) {
			if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
				return CONTINUE_LOOP;
			} else {
				return ABORT_LOOP;
			}
		} else {
			if (likely(peer_function != NULL)) {
				peer_function(loop, peer_fd);
			}
		}
	/* coverity[leaked_handle] */
	}
}

static enum callback_return accept_jet(union io_context *io)
{
	struct io_event *ev = container_of(io, struct io_event, context);
	return accept_common(ev->loop, io, handle_new_jet_connection);
}

static enum callback_return accept_jet_error(union io_context *io)
{
	(void)io;
	return ABORT_LOOP;
}

static enum callback_return accept_http(union io_context *io)
{
	struct io_event *ev = container_of(io, struct io_event, context);
	return accept_common(ev->loop, io, handle_http);
}

static enum callback_return accept_http_error(union io_context *io)
{
	(void)io;
	return ABORT_LOOP;
}

static int start_server(struct io_event *ev)
{
	if (ev->loop->add(ev) == ABORT_LOOP) {
		return -1;
	} else {
		if (ev->read_function(&ev->context) == CONTINUE_LOOP) {
			return 0;
		} else {
			ev->loop->remove(ev);
			return -1;
		}
	}
}

static int create_server_socket(int server_port)
{
	int listen_fd;
	struct sockaddr_in6 serveraddr;
	static const int reuse_on = 1;

	listen_fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (listen_fd < 0) {
		log_err("Could not create listen socket!\n");
		return -1;
	}

	if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse_on,
			sizeof(reuse_on)) < 0) {
		log_err("Could not set %s!\n", "SO_REUSEADDR");
		return -1;
	}

	if (set_fd_non_blocking(listen_fd) < 0) {
		return -1;
	}

	memset(&serveraddr, 0, sizeof(serveraddr));
	serveraddr.sin6_family = AF_INET6;
	serveraddr.sin6_port = htons(server_port);
	serveraddr.sin6_addr = in6addr_any;
	if (bind(listen_fd, (struct sockaddr *)&serveraddr,
		sizeof(serveraddr)) < 0) {
		log_err("bind failed!\n");
		return -1;
	}

	if (listen(listen_fd, CONFIG_LISTEN_BACKLOG) < 0) {
		log_err("listen failed!\n");
		return -1;
	}
	return listen_fd;
}

static void stop_server(struct io_event *ev)
{
	ev->loop->remove(ev);
	close(ev->context.fd);
}

static void sighandler(int signum)
{
	(void)signum;
	go_ahead = 0;
}

static int register_signal_handler(void)
{
	if (signal(SIGTERM, sighandler) == SIG_ERR) {
		log_err("installing signal handler for SIGTERM failed!\n");
		return -1;
	}
	if (signal(SIGINT, sighandler) == SIG_ERR) {
		log_err("installing signal handler for SIGINT failed!\n");
		signal(SIGTERM, SIG_DFL);
		return -1;
	}
	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
		log_err("ignoring SIGPIPE failed!\n");
		return -1;
	}
	return 0;
}

static void unregister_signal_handler(void)
{
	signal(SIGINT, SIG_DFL);
	signal(SIGTERM, SIG_DFL);
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

int run_io(const struct eventloop *loop, const char *user_name)
{
	int ret = 0;

	if (register_signal_handler() < 0) {
		return -1;
	}

	if (loop->create() < 0) {
		go_ahead = 0;
		ret = -1;
		goto unregister_signal_handler;
	}

	int jet_fd = create_server_socket(CONFIG_JET_PORT);
	if (jet_fd < 0) {
		goto eventloop_destroy;
	}

	struct jet_server jet_server = {
		.ev = {
			.read_function = accept_jet,
			.write_function = NULL,
			.error_function = accept_jet_error,
			.loop = loop,
			.context.fd = jet_fd
		}
	};

	ret = start_server(&jet_server.ev);
	if (ret  < 0) {
		close(jet_fd);
		goto eventloop_destroy;
	}

	int http_fd = create_server_socket(CONFIG_JETWS_PORT);
	if (http_fd < 0) {
		goto stop_jet_server;
	}
	
	struct http_server h_server = {
		.ev = {
			.read_function = accept_http,
			.write_function = NULL,
			.error_function = accept_http_error,
			.loop = loop,
			.context.fd = http_fd
		}
	};
	
	ret = start_server(&h_server.ev);
	if (ret  < 0) {
		close(http_fd);
		goto stop_jet_server;
	}

	if ((user_name != NULL) && drop_privileges(user_name) < 0) {
		go_ahead = 0;
		ret = -1;
		goto stop_http_server;
	}

	ret = loop->run(&go_ahead);

	destroy_all_peers();

stop_http_server:
	stop_server(&h_server.ev);
stop_jet_server:
	stop_server(&jet_server.ev);
eventloop_destroy:
	loop->destroy();
unregister_signal_handler:
	unregister_signal_handler();
	return ret;
}
