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
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "alloc.h"
#include "buffered_reader.h"
#include "compiler.h"
#include "eventloop.h"
#include "generated/os_config.h"
#include "http_connection.h"
#include "http_server.h"
#include "jet_server.h"
#include "linux/linux_io.h"
#include "log.h"
#include "socket_peer.h"
#include "util.h"
#include "websocket.h"
#include "websocket_peer.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

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


	return 0;
}

static int prepare_peer_socket(int fd)
{
	if (set_fd_non_blocking(fd) < 0) {
		log_err("Could not set socket to nonblocking '%s'!\n", strerror(errno));
		close(fd);
		return -1;
	}

	struct sockaddr_storage sockAddr;
	socklen_t sockAddrSize = sizeof(sockAddr);

	if (getsockname(fd, (struct sockaddr *)&sockAddr, &sockAddrSize) < 0) {
		log_err("could not determine socket domain '%s'", strerror(errno));
		return -1;
	}

	if ((sockAddr.ss_family == AF_INET) || (sockAddr.ss_family == AF_INET6)) {
		static const int tcp_nodelay_on = 1;

		if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &tcp_nodelay_on, sizeof(tcp_nodelay_on))==-1) {
			log_err("error turning off nagle algorithm '%s'", strerror(errno));
			return -1;
		}
		if (configure_keepalive(fd) < 0) {
			log_err("Could not configure keepalive '%s'!\n", strerror(errno));
			close(fd);
			return -1;
		}
	}

	// activate keep-alive
	int opt = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt)) == -1) {
		log_err("error setting socket option SO_KEEPALIVE '%s'\n", strerror(errno));
		return -1;
	}
	return 0;
}

static void handle_new_jet_connection(struct io_event *ev, int fd, bool is_local_connection)
{
	if (unlikely(prepare_peer_socket(fd) < 0)) {
		close(fd);
		return;
	}

	struct socket_peer *peer = alloc_jet_peer();
	if (unlikely(peer == NULL)) {
		log_err("Could not allocate jet peer!\n");
		goto alloc_peer_failed;
	}

	struct buffered_socket *bs = buffered_socket_acquire();
	if (unlikely(bs == NULL)) {
		log_err("Could not allocate buffered_socket");
		goto alloc_bs_failed;
	}
	buffered_socket_init(bs, (socket_type)fd, ev->loop, free_peer_on_error, peer);

	struct buffered_reader br;
	br.this_ptr = bs;
	br.close = buffered_socket_close;
	br.read_exactly = buffered_socket_read_exactly;
	br.read_until = buffered_socket_read_until;
	br.set_error_handler = buffered_socket_set_error;
	br.writev = buffered_socket_writev;

	init_socket_peer(peer, &br, is_local_connection);
	return;

alloc_bs_failed:
	cjet_free(peer);
alloc_peer_failed:
	close(fd);
}

static void handle_http(struct io_event *ev, int fd, bool is_local_connection)
{
	if (unlikely(prepare_peer_socket(fd) < 0)) {
		close(fd);
		return;
	}
	const struct http_server *server = const_container_of(ev, struct http_server, ev);
	struct http_connection *connection = alloc_http_connection();
	if (unlikely(connection == NULL)) {
		log_err("Could not allocate http connection!\n");
		goto alloc_failed;
	}

	struct buffered_socket *bs = buffered_socket_acquire();
	if (unlikely(bs == NULL)) {
		log_err("Could not allocate buffered_socket");
		goto alloc_bs_failed;
	}
	buffered_socket_init(bs, (socket_type)fd, ev->loop, free_connection, connection);

	struct buffered_reader br;
	br.this_ptr = bs;
	br.close = buffered_socket_close;
	br.read_exactly = buffered_socket_read_exactly;
	br.read_until = buffered_socket_read_until;
	br.set_error_handler = buffered_socket_set_error;
	br.writev = buffered_socket_writev;

	int ret = init_http_connection(connection, server, &br, is_local_connection);
	if (unlikely(ret < 0)) {
		log_err("Could not initialize http connection!\n");
		goto init_failed;
	}
	return;

init_failed:
	cjet_free(bs);
alloc_bs_failed:
	cjet_free(connection);
alloc_failed:
	close(fd);
}

static bool is_localhost(const struct sockaddr_storage *addr)
{
	if (addr->ss_family == AF_INET) {
		static const uint8_t ipv4_localhost_bytes[] =
		    {0x7f, 0, 0, 1};
		const struct sockaddr_in *s = (const struct sockaddr_in *)addr;
		if (memcmp(ipv4_localhost_bytes, &s->sin_addr.s_addr, sizeof(ipv4_localhost_bytes)) == 0) {
			return true;
		} else {
			return false;
		}
	} else {
		static const uint8_t mapped_ipv4_localhost_bytes[] =
		    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0x7f, 0, 0, 1};
		static const uint8_t localhost_bytes[] =
		    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

		const struct sockaddr_in6 *s = (const struct sockaddr_in6 *)addr;
		if ((memcmp(mapped_ipv4_localhost_bytes, s->sin6_addr.s6_addr, sizeof(mapped_ipv4_localhost_bytes)) == 0) ||
		    (memcmp(localhost_bytes, s->sin6_addr.s6_addr, sizeof(localhost_bytes)) == 0)) {
			return true;
		} else {
			return false;
		}
	}
}

static enum eventloop_return accept_common(struct io_event *ev, void (*peer_function)(struct io_event *ev, int fd, bool is_local_connection))
{
	while (1) {
		struct sockaddr_storage addr;
		memset(&addr, 0, sizeof(addr));
		socklen_t addrlen = sizeof(addr);
		int peer_fd = accept(ev->sock, (struct sockaddr *)&addr, &addrlen);
		if (peer_fd == -1) {
			if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
				return EL_CONTINUE_LOOP;
			} else {
				return EL_ABORT_LOOP;
			}
		} else {
			if (likely(peer_function != NULL)) {
				bool is_local = is_localhost(&addr);
				peer_function(ev, peer_fd, is_local);
			} else {
				close(peer_fd);
			}
		}
	}
}

static enum eventloop_return accept_jet(struct io_event *ev)
{
	return accept_common(ev, handle_new_jet_connection);
}

static enum eventloop_return accept_jet_error(struct io_event *ev)
{
	(void)ev;
	return EL_ABORT_LOOP;
}

static enum eventloop_return accept_http(struct io_event *ev)
{
	return accept_common(ev, handle_http);
}

static enum eventloop_return accept_http_error(struct io_event *ev)
{
	(void)ev;
	return EL_ABORT_LOOP;
}

static int start_server(struct io_event *ev)
{
	if (ev->loop->add(ev->loop->this_ptr, ev) == EL_ABORT_LOOP) {
		return -1;
	} else {
		if (ev->read_function(ev) == EL_CONTINUE_LOOP) {
			return 0;
		} else {
			ev->loop->remove(ev->loop->this_ptr, ev);
			return -1;
		}
	}
}

static int create_server_socket_all_interfaces(int port)
{
	int listen_fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (unlikely(listen_fd < 0)) {
		log_err("Could not create listen socket!\n");
		return -1;
	}

	static const int reuse_on = 1;
	if (unlikely(setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse_on,
	                        sizeof(reuse_on)) < 0)) {
		log_err("Could not set %s!\n", "SO_REUSEADDR");
		goto error;
	}

	if (unlikely(set_fd_non_blocking(listen_fd) < 0)) {
		log_err("Could not set %s!\n", "O_NONBLOCK");
		goto error;
	}

	struct sockaddr_in6 serveraddr;
	memset(&serveraddr, 0, sizeof(serveraddr));
	serveraddr.sin6_family = AF_INET6;
	serveraddr.sin6_port = htons(port);
	serveraddr.sin6_addr = in6addr_any;
	if (unlikely(bind(listen_fd, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0)) {
		log_err("bind failed: '%s'!\n", strerror(errno));
		goto error;
	}

	if (unlikely(listen(listen_fd, CONFIG_LISTEN_BACKLOG) < 0)) {
		log_err("listen failed!\n");
		goto error;
	}

	return listen_fd;

error:
	close(listen_fd);
	return -1;
}

static int create_server_unix_domain_socket(const char *pPath)
{
	struct sockaddr_un serveraddr;
	/* abstract socket address is distinguished by putting '\0' in the first byte of the address
	 * addrlen for bind has to be calculated! This includes the address prefix '\0'
	*/
	size_t serveraddrLen = 1+strlen(pPath)+sizeof(serveraddr.sun_family);
	memset(&serveraddr, 0, sizeof(serveraddr));
	serveraddr.sun_family = AF_UNIX;
	strncpy(&serveraddr.sun_path[1], pPath, sizeof(serveraddr.sun_path) - 2);

	int listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (unlikely(listen_fd < 0)) {
		log_err("Could not create listen socket!\n");
		return -1;
	}

	static const int reuse_on = 1;
	if (unlikely(setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse_on,
							sizeof(reuse_on)) < 0)) {
		log_err("Could not set %s!\n", "SO_REUSEADDR");
		goto error;
	}

	if (unlikely(set_fd_non_blocking(listen_fd) < 0)) {
		log_err("Could not set %s!\n", "O_NONBLOCK");
		goto error;
	}

	if (unlikely(bind(listen_fd, (struct sockaddr *)&serveraddr, (socklen_t)serveraddrLen) < 0)) {
		log_err("binding unix domain socket failed: '%s!\n", strerror(errno));
		goto error;
	}

	if (unlikely(listen(listen_fd, CONFIG_LISTEN_BACKLOG) < 0)) {
		log_err("listen failed!\n");
		goto error;
	}

	return listen_fd;

error:
	close(listen_fd);
	return -1;
}

static int start_uds_server(struct eventloop *loop, struct jet_server* pjet_uds_server)
{
	int uds_fd = create_server_unix_domain_socket(UDS_FILE);
	if (uds_fd < 0) {
		return -1;
	}

	pjet_uds_server->ev.read_function = accept_jet;
	pjet_uds_server->ev.write_function = NULL;
	pjet_uds_server->ev.error_function = accept_jet_error;
	pjet_uds_server->ev.loop = loop;
	pjet_uds_server->ev.sock = uds_fd;

	int ret = start_server(&pjet_uds_server->ev);
	if (ret < 0) {
		close(uds_fd);
		return -1;
	}
	return 0;
}



static int create_server_socket_bound(const char *bind_addr, int port)
{
	struct addrinfo hints;
	struct addrinfo *servinfo;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE | AI_V4MAPPED | AI_NUMERICHOST;

	char server_port_string[6];
	sprintf(server_port_string, "%d", port);

	int ret = getaddrinfo(bind_addr, server_port_string, &hints, &servinfo);
	if (ret != 0) {
		log_err("Could not set resolve address to bind!");
		return -1;
	}

	int listen_fd = -1;
	struct addrinfo *rp;
	for (rp = servinfo; rp != NULL; rp = rp->ai_next) {
		listen_fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (listen_fd == -1) {
			continue;
		}

		static const int reuse_on = 1;
		if (unlikely(setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse_on,
		                        sizeof(reuse_on)) < 0)) {
			log_err("Could not set %s!\n", "SO_REUSEADDR");
			close(listen_fd);
			continue;
		}

		if (rp->ai_family == AF_INET6) {
			static const int ipv6_only = 1;
			if (unlikely(setsockopt(listen_fd, IPPROTO_IPV6, IPV6_V6ONLY, &ipv6_only,
			                        sizeof(ipv6_only)) < 0)) {
				log_err("Could not set %s!\n", "IPV6_V6ONLY");
				close(listen_fd);
				continue;
			}
		}

		if (unlikely(set_fd_non_blocking(listen_fd) < 0)) {
			log_err("Could not set %s!\n", "O_NONBLOCK");
			close(listen_fd);
			continue;
		}

		if (bind(listen_fd, rp->ai_addr, rp->ai_addrlen) == 0) {
			break;
		}
		close(listen_fd);
	}

	freeaddrinfo(servinfo);

	if ((listen_fd == -1) || (rp == NULL)) {
		log_err("Could not bind to address!");
		return -1;
	}

	if (unlikely(listen(listen_fd, CONFIG_LISTEN_BACKLOG) < 0)) {
		log_err("listen failed!\n");
		close(listen_fd);
		return -1;
	}

	return listen_fd;
}

static void stop_server(struct io_event *ev)
{
	ev->loop->remove(ev->loop->this_ptr, ev);
	close(ev->sock);
}

static void stop_uds_server(struct io_event *ev)
{
	ev->loop->remove(ev->loop->this_ptr, ev);
	close(ev->sock);
	unlink(UDS_FILE);
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

static int run_jet(const struct eventloop *loop, const struct cmdline_config *config)
{
	if ((config->user_name != NULL) && drop_privileges(config->user_name) < 0) {
		log_err("Can't drop privileges of cjet!\n");
		return -1;
	}

	if (!config->run_foreground) {
		if (daemon(0, 0) != 0) {
			log_err("Can't daemonize cjet!\n");
			return -1;
		}
	}

	int ret = loop->run(loop->this_ptr, &go_ahead);
	destroy_all_peers();
	return ret;
}

static int run_io_only_local(struct eventloop *loop, const struct cmdline_config *config, const struct url_handler *handler, size_t num_handlers)
{
	int ret = 0;

	// start jet server on ipv6 loopback
	int ipv6_jet_fd = create_server_socket_bound("::1", CONFIG_JET_PORT);
	if (ipv6_jet_fd < 0) {
		return -1;
	}
	struct jet_server ipv6_jet_server = {
	    .ev = {
	        .read_function = accept_jet,
	        .write_function = NULL,
	        .error_function = accept_jet_error,
	        .loop = loop,
	        .sock = ipv6_jet_fd}};
	ret = start_server(&ipv6_jet_server.ev);
	if (ret < 0) {
		close(ipv6_jet_fd);
		return -1;
	}

	// start jet server on ipv4 loopback
	int ipv4_jet_fd = create_server_socket_bound("127.0.0.1", CONFIG_JET_PORT);
	if (ipv4_jet_fd < 0) {
		ret = -1;
		goto create_ipv4_jet_socket_failed;
	}

	struct jet_server ipv4_jet_server = {
	    .ev = {
	        .read_function = accept_jet,
	        .write_function = NULL,
	        .error_function = accept_jet_error,
	        .loop = loop,
	        .sock = ipv4_jet_fd}};
	ret = start_server(&ipv4_jet_server.ev);
	if (ret < 0) {
		close(ipv4_jet_fd);
		goto start_ipv4_jet_server_failed;
	}

	// start websocket jet server on ipv6 loopback
	int ipv6_http_fd = create_server_socket_bound("::1", CONFIG_JETWS_PORT);
	if (ipv6_http_fd < 0) {
		ret = -1;
		goto create_ipv6_jetws_socket_failed;
	}

	struct http_server ipv6_http_server = {
	    .ev = {
	        .read_function = accept_http,
	        .write_function = NULL,
	        .error_function = accept_http_error,
	        .loop = loop,
	        .sock = ipv6_http_fd},
	    .handler = handler,
	    .num_handlers = num_handlers};
	ret = start_server(&ipv6_http_server.ev);
	if (ret < 0) {
		close(ipv6_http_fd);
		goto start_ipv6_jetws_server_failed;
	}

	// start websocket jet server on ipv4 loopback
	int ipv4_http_fd = create_server_socket_bound("127.0.0.1", CONFIG_JETWS_PORT);
	if (ipv4_http_fd < 0) {
		ret = -1;
		goto create_ipv4_jetws_socket_failed;
	}

	struct http_server ipv4_http_server = {
	    .ev = {
	        .read_function = accept_http,
	        .write_function = NULL,
	        .error_function = accept_http_error,
	        .loop = loop,
	        .sock = ipv4_http_fd},
	    .handler = handler,
	    .num_handlers = num_handlers};
	ret = start_server(&ipv4_http_server.ev);
	if (ret < 0) {
		close(ipv4_http_fd);
		goto start_ipv4_jetws_server_failed;
	}

	struct jet_server uds_jet_server;
	if (start_uds_server(loop, &uds_jet_server) < 0) {
		ret = -1;
		goto start_uds_server_failed;
	}

	ret = run_jet(loop, config);

	stop_uds_server(&uds_jet_server.ev);
start_uds_server_failed:
	stop_server(&ipv4_http_server.ev);
start_ipv4_jetws_server_failed:
create_ipv4_jetws_socket_failed:
	stop_server(&ipv6_http_server.ev);
start_ipv6_jetws_server_failed:
create_ipv6_jetws_socket_failed:
	stop_server(&ipv4_jet_server.ev);
start_ipv4_jet_server_failed:
create_ipv4_jet_socket_failed:
	stop_server(&ipv6_jet_server.ev);
	return ret;
}

static int run_io_all_interfaces(struct eventloop *loop, const struct cmdline_config *config, const struct url_handler *handler, size_t num_handlers)
{
	int ret = 0;

	int jet_fd = create_server_socket_all_interfaces(CONFIG_JET_PORT);
	if (jet_fd < 0) {
		return -1;
	}

	struct jet_server jet_server = {
	    .ev = {
	        .read_function = accept_jet,
	        .write_function = NULL,
	        .error_function = accept_jet_error,
	        .loop = loop,
	        .sock = jet_fd}};
	ret = start_server(&jet_server.ev);
	if (ret < 0) {
		close(jet_fd);
		return -1;
	}

	int http_fd = create_server_socket_all_interfaces(CONFIG_JETWS_PORT);
	if (http_fd < 0) {
		ret = -1;
		goto create_jetws_socket_failed;
	}

	struct http_server http_server = {
	    .ev = {
	        .read_function = accept_http,
	        .write_function = NULL,
	        .error_function = accept_http_error,
	        .loop = loop,
	        .sock = http_fd},
	    .handler = handler,
	    .num_handlers = num_handlers};
	ret = start_server(&http_server.ev);
	if (ret < 0) {
		close(http_fd);
		goto start_jetws_server_failed;
	}

	struct jet_server uds_jet_server;
	if (start_uds_server(loop, &uds_jet_server) < 0) {
		ret = -1;
		goto start_local_uds_server_failed;
	}

	ret = run_jet(loop, config);

	stop_uds_server(&uds_jet_server.ev);
start_local_uds_server_failed:
	stop_server(&http_server.ev);
start_jetws_server_failed:
create_jetws_socket_failed:
	stop_server(&jet_server.ev);
	return ret;
}

int run_io(struct eventloop *loop, const struct cmdline_config *config)
{
	int ret;

	if (register_signal_handler() < 0) {
		return -1;
	}

	if (loop->init(loop->this_ptr) < 0) {
		go_ahead = 0;
		ret = -1;
		goto eventloop_init_failed;
	}

	const struct url_handler handler[] = {
	    {
	        .request_target = config->request_target,
	        .create = alloc_websocket_peer,
	        .on_header_field = websocket_upgrade_on_header_field,
	        .on_header_value = websocket_upgrade_on_header_value,
	        .on_headers_complete = websocket_upgrade_on_headers_complete,
	        .on_body = NULL,
	        .on_message_complete = NULL,
	    },
	};

	if (config->bind_local_only) {
		ret = run_io_only_local(loop, config, handler, ARRAY_SIZE(handler));
	} else {
		ret = run_io_all_interfaces(loop, config, handler, ARRAY_SIZE(handler));
	}

	loop->destroy(loop->this_ptr);
eventloop_init_failed:
	unregister_signal_handler();
	return ret;
}
