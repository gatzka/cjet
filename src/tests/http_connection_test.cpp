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

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))

static bool close_called = false;

static const char *readbuffer;
static const char *readbuffer_ptr;
static size_t readbuffer_length;

static const int FD_WOULDBLOCK = 1;
static const int FD_COMPLETE_STARTLINE = 2;

extern "C" {
	ssize_t socket_writev(socket_type sock, struct buffered_socket_io_vector *io_vec, unsigned int count)
	{
		(void)io_vec;
		(void)count;

		switch (sock) {
		case FD_WOULDBLOCK:
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
		case FD_WOULDBLOCK:
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
		case FD_COMPLETE_STARTLINE:
			if (readbuffer_length > 0) {
				size_t len = MIN(readbuffer_length, count);
				memcpy(buf, readbuffer_ptr, len);
				readbuffer_length -= len;
				readbuffer_ptr += len;
				return len;
			} else {
				errno = EWOULDBLOCK;
				return -1;
			}
			break;
		
		case FD_WOULDBLOCK:
		default:
			errno = EWOULDBLOCK;
			return -1;
		}
	}

	int socket_close(socket_type sock)
	{
		(void)sock;
		close_called = true;
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
		close_called = false;

		loop.create = NULL;
		loop.destroy = NULL;
		loop.run = NULL;
		loop.add = eventloop_fake_add;
		loop.remove = eventloop_fake_remove;

		readbuffer_ptr = readbuffer;
	}

	~F()
	{
	}

	struct eventloop loop;
};

BOOST_AUTO_TEST_CASE(test_websocket_alloc)
{
	F f;
	struct http_connection *connection = alloc_http_connection(NULL, &f.loop, FD_WOULDBLOCK);
	BOOST_CHECK_MESSAGE(connection != NULL, "Connection allocation failed!");
	
	free_connection(connection);
}

BOOST_AUTO_TEST_CASE(test_buffered_socket_migration)
{
	F f;
	struct http_connection *connection = alloc_http_connection(NULL, &f.loop, FD_WOULDBLOCK);
	BOOST_CHECK(connection != NULL);

	struct buffered_socket *bs = connection->bs;
	connection->bs = NULL;
	free_connection(connection);
	BOOST_CHECK_MESSAGE(!close_called, "Close was called after buffered_socket migration!");
	buffered_socket_close(bs);
	free(bs);
	BOOST_CHECK_MESSAGE(close_called, "Close was not called after buffered_socket_close!");
}

#if 0
BOOST_AUTO_TEST_CASE(test_read_correct_startline)
{
	readbuffer = "aaaa\r\n";
	readbuffer_length = ::strlen(readbuffer);
	F f;
	struct http_connection *connection = alloc_http_connection(NULL, &f.loop, FD_COMPLETE_STARTLINE);
	BOOST_CHECK(connection != NULL);

	free_connection(connection);
}

#endif
