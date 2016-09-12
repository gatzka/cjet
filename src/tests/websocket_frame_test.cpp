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
#define BOOST_TEST_MODULE websocket_frame_tests

#include <boost/test/unit_test.hpp>
#include <errno.h>

#include "jet_endian.h"
#include "jet_string.h"
#include "socket.h"
#include "buffered_socket.h"
#include "websocket.h"

#define CRLF "\r\n"

#ifndef ARRAY_SIZE
 #define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

static char write_buffer[5000];
static char *write_buffer_ptr;

static http_parser response_parser;
static http_parser_settings response_parser_settings;
static bool got_complete_response_header = false;
static bool response_parse_error = false;

extern "C" {
	ssize_t socket_writev(socket_type sock, struct buffered_socket_io_vector *io_vec, unsigned int count)
	{
		(void)sock;
		size_t complete_length = 0;
		for (unsigned int i = 0; i < count; i++) {
			if (!got_complete_response_header) {
				size_t nparsed = http_parser_execute(&response_parser, &response_parser_settings, (const char *)io_vec[i].iov_base, io_vec[i].iov_len);
				if (nparsed != io_vec[i].iov_len) {
					response_parse_error = true;
					errno = EFAULT;
					return -1;
				}
				} else {
				memcpy(write_buffer_ptr, io_vec[i].iov_base, io_vec[i].iov_len);
				write_buffer_ptr += io_vec[i].iov_len;
			}
			complete_length += io_vec[i].iov_len;
		}
		return complete_length;
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

static enum eventloop_return eventloop_fake_add(const void *this_ptr, const struct io_event *ev)
{
	(void)this_ptr;
	(void)ev;
	return EL_CONTINUE_LOOP;
}

static void eventloop_fake_remove(const void *this_ptr, const struct io_event *ev)
{
	(void)this_ptr;
	(void)ev;
}

static void ws_on_error(struct websocket *ws)
{
	(void)ws;
}

struct F {

	F()
	{
		write_buffer_ptr = write_buffer;
		loop.init = NULL;
		loop.destroy = NULL;
		loop.run = NULL;
		loop.add = eventloop_fake_add;
		loop.remove = eventloop_fake_remove;

		struct buffered_socket *bs = (struct buffered_socket *)malloc(sizeof(*bs));
		buffered_socket_init(bs, 12, &loop, NULL, NULL);
		websocket_init(&ws, NULL, true, ws_on_error, "jet");
		ws.bs = bs;
		ws.connection = NULL;
	}

	~F()
	{
		websocket_free(&ws);
	}

	struct eventloop loop;
	struct websocket ws;
};

BOOST_FIXTURE_TEST_CASE(websocket_correct_text_frame, F)
{
	BOOST_CHECK_MESSAGE(1 == 1, "got it");
}

