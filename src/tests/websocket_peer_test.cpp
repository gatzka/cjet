/*
 * The MIT License (MIT)
 *
 * Copyright (c) <2015> <Stephan Gatzka>
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

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MAIN
#define BOOST_TEST_MODULE websocket_peer

#include <boost/test/unit_test.hpp>

#include "buffered_reader.h"
#include "generated/os_config.h"
#include "http_connection.h"
#include "peer.h"
#include "socket.h"
#include "websocket_peer.h"

static unsigned int num_close_called = 0;

extern "C" {

	ssize_t socket_read(socket_type sock, void *buf, size_t count)
	{
		(void)sock;
		(void)count;
		uint64_t number_of_timeouts = 1;
		::memcpy(buf, &number_of_timeouts, sizeof(number_of_timeouts));
		return 8;
	}

	int socket_close(socket_type sock)
	{
		(void)sock;
		return 0;
	}

	static int br_read_exactly(void *this_ptr, size_t num, read_handler handler, void *handler_context) {
		(void)this_ptr;
		(void)num;
		(void)handler;
		(void)handler_context;
		return 0;
	}

	static int br_read_until(void *this_ptr, const char *delim, read_handler handler, void *handler_context) {
		(void)this_ptr;
		(void)delim;
		(void)handler;
		(void)handler_context;
		return 0;
	}

	static int br_writev(void *this_ptr, struct socket_io_vector *io_vec, unsigned int count) {
		(void)this_ptr;
		(void)io_vec;
		(void)count;
		return 0;
	}

	static int br_close(void *this_ptr) {
		(void)this_ptr;
		num_close_called++;
		return 0;
	}

	static void br_set_error_handler(void *this_ptr, error_handler handler, void *error_context) {
		(void)this_ptr;
		(void)handler;
		(void)error_context;
		return;
	}
}

BOOST_AUTO_TEST_CASE(test_connection_closed_when_destryoing_peers)
{
	struct buffered_reader br;
	br.this_ptr = NULL;
	br.close = br_close;
	br.read_exactly = br_read_exactly;
	br.read_until = br_read_until;
	br.set_error_handler = br_set_error_handler;
	br.writev = br_writev;

	struct http_server server;
	server.ev.loop = NULL;

	struct http_connection *connection = alloc_http_connection();
	init_http_connection(connection, &server, &br, false);

	int ret = alloc_websocket_peer(connection);
	BOOST_REQUIRE_MESSAGE(ret == 0, "alloc_websocket_peer did not return 0");

	destroy_all_peers();
	BOOST_CHECK_MESSAGE(num_close_called == 1, "Close of buffered_reader was not called when websocket is closed!");
}

