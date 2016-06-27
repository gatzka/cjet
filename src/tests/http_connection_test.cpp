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
#define BOOST_TEST_MODULE http_connection_tests

#include <boost/test/unit_test.hpp>
#include <errno.h>

#include "buffered_socket.h"
#include "eventloop.h"
#include "http_connection.h"
#include "socket.h"

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))

#ifndef ARRAY_SIZE
 #define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

static bool close_called = false;
static bool create_called = false;

static const char *readbuffer;
static const char *readbuffer_ptr;
static size_t readbuffer_length;

static char write_buffer[5000];
size_t write_buffer_written;
static char *write_buffer_ptr;

static const int FD_WOULDBLOCK = 1;
static const int FD_COMPLETE_STARTLINE = 2;
static const int FD_CLOSE = 3;
static const int FD_ERROR = 4;

extern "C" {
	ssize_t socket_writev(socket_type sock, struct buffered_socket_io_vector *io_vec, unsigned int count)
	{
		(void)io_vec;
		(void)count;

		switch (sock) {
		case FD_COMPLETE_STARTLINE: {
			size_t complete_length = 0;
			for (unsigned int i = 0; i < count; i++) {
				memcpy(write_buffer_ptr, io_vec[i].iov_base, io_vec[i].iov_len);
				complete_length += io_vec[i].iov_len;
				write_buffer_ptr += io_vec[i].iov_len;
			}
			write_buffer_written = complete_length;
			return complete_length;
		}
		
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
		
		case FD_CLOSE:
			return 0;

		case FD_ERROR:
			errno = EINVAL;
			return -1;

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

int on_create(struct http_connection *connection)
{
	(void)connection;
	create_called = true;
	return 0;
}

struct F {
	F()
	{
		close_called = false;
		create_called = false;

		loop.init = NULL;
		loop.destroy = NULL;
		loop.run = NULL;
		loop.add = eventloop_fake_add;
		loop.remove = eventloop_fake_remove;

		readbuffer_ptr = readbuffer;
		write_buffer_ptr = write_buffer;
		write_buffer_written = 0;

		http_parser_settings_init(&parser_settings);
		http_parser_init(&parser, HTTP_RESPONSE);

		handler[0].request_target = "/";
		handler[0].create = NULL;
		handler[0].on_header_field = NULL;
		handler[0].on_header_value = NULL;
		handler[0].on_headers_complete = NULL;
		handler[0].on_body = NULL;
		handler[0].on_message_complete = NULL;

		http_server.handler = handler;
		http_server.num_handlers = ARRAY_SIZE(handler);
	}

	~F()
	{
	}

	struct eventloop loop;
	http_parser parser;
	http_parser_settings parser_settings;
	struct url_handler handler[1];
	struct http_server http_server;
};

BOOST_FIXTURE_TEST_CASE(test_websocket_alloc, F)
{
	struct http_connection *connection = alloc_http_connection(NULL, &loop, FD_WOULDBLOCK);
	BOOST_CHECK_MESSAGE(connection != NULL, "Connection allocation failed!");
	
	free_connection(connection);
}

BOOST_FIXTURE_TEST_CASE(test_buffered_socket_migration, F)
{
	struct http_connection *connection = alloc_http_connection(NULL, &loop, FD_WOULDBLOCK);
	BOOST_CHECK(connection != NULL);

	struct buffered_socket *bs = connection->bs;
	connection->bs = NULL;
	free_connection(connection);
	BOOST_CHECK_MESSAGE(!close_called, "Close was called after buffered_socket migration!");
	buffered_socket_close(bs);
	free(bs);
	BOOST_CHECK_MESSAGE(close_called, "Close was not called after buffered_socket_close!");
}

BOOST_FIXTURE_TEST_CASE(test_read_invalid_startline, F)
{
	readbuffer = "aaaa\r\n";
	readbuffer_ptr = readbuffer;
	readbuffer_length = ::strlen(readbuffer);
	struct http_connection *connection = alloc_http_connection(NULL, &loop, FD_COMPLETE_STARTLINE);
	BOOST_CHECK(connection == NULL);
}

BOOST_FIXTURE_TEST_CASE(test_read_close, F)
{
	readbuffer = "aaaa\r\n";
	readbuffer_ptr = readbuffer;
	readbuffer_length = ::strlen(readbuffer);
	struct http_connection *connection = alloc_http_connection(NULL, &loop, FD_CLOSE);
	BOOST_CHECK(connection == NULL);
}

BOOST_FIXTURE_TEST_CASE(test_read_error, F)
{
	readbuffer = "aaaa\r\n";
	readbuffer_ptr = readbuffer;
	readbuffer_length = ::strlen(readbuffer);
	struct http_connection *connection = alloc_http_connection(NULL, &loop, FD_ERROR);
	BOOST_CHECK(connection == NULL);
}

BOOST_FIXTURE_TEST_CASE(test_read_valid_startline_url_match, F)
{
	readbuffer = "GET /infotext.html HTTP/1.1\r\n";
	readbuffer_ptr = readbuffer;
	readbuffer_length = ::strlen(readbuffer);
	struct http_connection *connection = alloc_http_connection(&http_server, &loop, FD_COMPLETE_STARTLINE);
	BOOST_CHECK(connection != NULL);

	free_connection(connection);
}

BOOST_FIXTURE_TEST_CASE(test_read_valid_startline_url_match_create_called, F)
{
	handler[0].create = on_create;
	readbuffer = "GET /infotext.html HTTP/1.1\r\n";
	readbuffer_ptr = readbuffer;
	readbuffer_length = ::strlen(readbuffer);
	struct http_connection *connection = alloc_http_connection(&http_server, &loop, FD_COMPLETE_STARTLINE);
	BOOST_CHECK(connection != NULL);
	BOOST_CHECK_MESSAGE(create_called, "Create callback was not called!");

	free_connection(connection);
}

BOOST_FIXTURE_TEST_CASE(test_read_valid_startline_url_no_match, F)
{
	handler[0].request_target = "/foobar/";

	readbuffer = "GET /infotext.html HTTP/1.1\r\n";
	readbuffer_ptr = readbuffer;
	readbuffer_length = ::strlen(readbuffer);
	struct http_connection *connection = alloc_http_connection(&http_server, &loop, FD_COMPLETE_STARTLINE);
	BOOST_CHECK(connection == NULL);
	
	size_t nparsed = http_parser_execute(&parser, &parser_settings, write_buffer, write_buffer_written);
	BOOST_CHECK(nparsed == write_buffer_written);
	BOOST_CHECK(parser.status_code == 404);
}

BOOST_FIXTURE_TEST_CASE(test_read_valid_startline_invalid_url, F)
{
	handler[0].request_target = "/foobar/";

	readbuffer = "GET http://ww%.google.de/ HTTP/1.1\r\n";
	readbuffer_ptr = readbuffer;
	readbuffer_length = ::strlen(readbuffer);
	struct http_connection *connection = alloc_http_connection(&http_server, &loop, FD_COMPLETE_STARTLINE);
	BOOST_CHECK(connection == NULL);

	size_t nparsed = http_parser_execute(&parser, &parser_settings, write_buffer, write_buffer_written);
	BOOST_CHECK(nparsed == write_buffer_written);
	BOOST_CHECK(parser.status_code == 400);
}

BOOST_FIXTURE_TEST_CASE(test_read_valid_startline_connect_request_url_match, F)
{
	readbuffer = "CONNECT www.example.com:443 HTTP/1.1\r\n";
	readbuffer_ptr = readbuffer;
	readbuffer_length = ::strlen(readbuffer);
	struct http_connection *connection = alloc_http_connection(&http_server, &loop, FD_COMPLETE_STARTLINE);
	BOOST_CHECK(connection == NULL);

	size_t nparsed = http_parser_execute(&parser, &parser_settings, write_buffer, write_buffer_written);
	BOOST_CHECK(nparsed == write_buffer_written);
	BOOST_CHECK(parser.status_code == 400);
}
