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

#include "buffered_socket.h"
#include "eventloop.h"
#include "http_connection.h"
#include "socket.h"

extern "C" {
	ssize_t socket_writev(socket_type sock, struct buffered_socket_io_vector *io_vec, unsigned int count)
	{
		(void)sock;
		(void)io_vec;
		(void)count;
		errno = EWOULDBLOCK;
		return -1;
	}

	ssize_t socket_send(socket_type sock, const void *buf, size_t len)
	{
		(void)sock;
		(void)buf;
		return len;
	}

	ssize_t socket_read(socket_type sock, void *buf, size_t count)
	{
		(void)sock;
		(void)buf;
		(void)count;
		errno = EWOULDBLOCK;
		return -1;
	}
	
	int socket_close(socket_type sock)
	{
		(void)sock;
		return 0;
	}
}

static enum callback_return eventloop_fake_add(struct io_event *ev)
{
	(void)ev;
	return CONTINUE_LOOP;
}

static void eventloop_fake_remove(struct io_event *ev)
{
	(void)ev;
}

struct F {
	F()
	{
		loop.create = NULL;
		loop.destroy = NULL;
		loop.run = NULL;
		loop.add = eventloop_fake_add;
		loop.remove = eventloop_fake_remove;

		ev.loop = &loop;
	}

	~F()
	{
	}

	struct eventloop loop;
	struct io_event ev;

};


BOOST_AUTO_TEST_CASE(test_websocket_alloc)
{
	F f;
	struct http_connection *connection = alloc_http_connection(&f.ev, 1);
	BOOST_CHECK(connection != NULL);
	
	free_connection(connection);
}
