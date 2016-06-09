/*
 *The MIT License (MIT)
 *
 * Copyright (c) <2016> <Stephan Gatzka>
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
#define BOOST_TEST_MODULE websocket_tests

#include <boost/test/unit_test.hpp>
#include <errno.h>

#include "socket.h"
#include "websocket.h"

extern "C" {
	ssize_t socket_writev(socket_type sock, struct buffered_socket_io_vector *io_vec, unsigned int count)
	{
		(void)io_vec;
		(void)count;

		switch (sock) {
		default:
			errno = EWOULDBLOCK;
			return -1;
		}
	}

	ssize_t socket_send(socket_type sock, const void *buf, size_t len)
	{
		(void)buf;
		(void)len;

		switch (sock) {
		default:
			errno = EWOULDBLOCK;
			return -1;
		}
	}

	ssize_t socket_read(socket_type sock, void *buf, size_t count)
	{
		(void)buf;
		(void)count;

		switch (sock) {
		default:
			errno = EWOULDBLOCK;
			return -1;
		}
	}

	int socket_close(socket_type sock)
	{
		(void)sock;
		return 0;
	}
}


BOOST_AUTO_TEST_CASE(test_websocket_init)
{
	struct websocket ws;
	websocket_init(&ws, NULL, true, NULL);
	websocket_free(&ws);
}
