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
#include <stdint.h>

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

static uint8_t readbuffer[5000];
static uint8_t *readbuffer_ptr;
static size_t readbuffer_length;

static char write_buffer[5000];
size_t write_buffer_written;
static char *write_buffer_ptr;


int on_create(struct http_connection *connection)
{
	(void)connection;
	create_called = true;
	return 0;
}

static int read_until(void *this_ptr, const char *delim,
                      enum bs_read_callback_return (*read_callback)(void *context, uint8_t *buf, size_t len),
                      void *callback_context)
{
	(void)this_ptr;
	(void)delim;
	
	read_callback(callback_context, readbuffer_ptr, readbuffer_length);
	return 0;
}

static int close(void *context)
{
	(void)context;
	close_called = true;
	return 0;
}

static int writev(void *this_ptr, struct buffered_socket_io_vector *io_vec, unsigned int count)
{
	(void)this_ptr;
	size_t complete_length = 0;
	for (unsigned int i = 0; i < count; i++) {
		memcpy(write_buffer_ptr, io_vec[i].iov_base, io_vec[i].iov_len);
		complete_length += io_vec[i].iov_len;
		write_buffer_ptr += io_vec[i].iov_len;
	}
	write_buffer_written = complete_length;
	return complete_length;
}

struct F {
	F()
	{
		connection = alloc_http_connection();
		br.this_ptr = this;
		br.close = close;
		br.read_exactly = NULL;
		br.read_until = read_until;
		br.set_error_handler = NULL;
		br.writev = writev;

		readbuffer_length = 0;
		readbuffer_ptr = readbuffer;
		write_buffer_ptr = write_buffer;
		write_buffer_written = 0;

		http_parser_settings_init(&parser_settings);
		http_parser_init(&parser, HTTP_RESPONSE);

		close_called = false;
		create_called = false;

		handler[0].request_target = "/";
		handler[0].create = NULL;
		handler[0].on_header_field = NULL;
		handler[0].on_header_value = NULL;
		handler[0].on_headers_complete = NULL;
		handler[0].on_body = NULL;
		handler[0].on_message_complete = NULL;

		http_server.handler = handler;
		http_server.num_handlers = ARRAY_SIZE(handler);

		http_server.ev.read_function = NULL;
		http_server.ev.write_function = NULL;
		http_server.ev.error_function = NULL;
		http_server.ev.loop = NULL;
		http_server.ev.sock = 0;
	}

	~F()
	{
	}

	bool check_http_response(int status_code)
	{
		size_t nparsed = http_parser_execute(&parser, &parser_settings, write_buffer, write_buffer_written);
		BOOST_REQUIRE_MESSAGE(nparsed == write_buffer_written, "Not a valid http response!");
		return parser.status_code == status_code;
	}

	struct url_handler handler[1];
	struct http_server http_server;

	struct http_connection *connection;
	struct buffered_reader br;
	http_parser parser;
	http_parser_settings parser_settings;
};

BOOST_FIXTURE_TEST_CASE(test_read_invalid_startline, F)
{
	const char message[] = "aaaa\r\n";
	::memcpy(readbuffer, message, sizeof(message));
	readbuffer_ptr = readbuffer;
	readbuffer_length = ::strlen(message);

	int ret = init_http_connection(connection, NULL, &br, false);
	BOOST_REQUIRE_MESSAGE(ret == 0, "Initialization failed for invalid start line!");
	BOOST_CHECK_MESSAGE(close_called, "Close was not called for invalid start_line");
	BOOST_CHECK_MESSAGE(check_http_response(400), "No \"bad request\" response for invalid start line!");
}

BOOST_FIXTURE_TEST_CASE(test_read_empty_startline, F)
{
	const char message[] = "";
	::memcpy(readbuffer, message, sizeof(message));
	readbuffer_ptr = readbuffer;
	readbuffer_length = ::strlen(message);

	int ret = init_http_connection(connection, NULL, &br, false);
	BOOST_REQUIRE_MESSAGE(ret == 0, "Initialization failed for empty start line!");
	BOOST_CHECK_MESSAGE(close_called, "Close was not called for empty start_line");
}

BOOST_FIXTURE_TEST_CASE(test_read_valid_startline_url_match, F)
{
	const char message[] = "GET /infotext.html HTTP/1.1\r\n";
	::memcpy(readbuffer, message, sizeof(message));
	readbuffer_ptr = readbuffer;
	readbuffer_length = ::strlen(message);

	int ret = init_http_connection(connection, &http_server, &br, false);
	BOOST_REQUIRE_MESSAGE(ret == 0, "Initialization failed for correct start line and URL match!");

	free_connection(connection);
}

BOOST_FIXTURE_TEST_CASE(test_read_valid_startline_url_match_create_called, F)
{
	handler[0].create = on_create;

	const char message[] = "GET /infotext.html HTTP/1.1\r\n";
	::memcpy(readbuffer, message, sizeof(message));
	readbuffer_ptr = readbuffer;
	readbuffer_length = ::strlen(message);

	int ret = init_http_connection(connection, &http_server, &br, false);
	BOOST_REQUIRE_MESSAGE(ret == 0, "Initialization failed for correct start line and URL match!");
	BOOST_CHECK_MESSAGE(create_called, "Create callback was not called!");

	free_connection(connection);
}

BOOST_FIXTURE_TEST_CASE(test_read_valid_startline_url_no_match, F)
{
	handler[0].request_target = "/foobar/";

	const char message[] = "GET /infotext.html HTTP/1.1\r\n";
	::memcpy(readbuffer, message, sizeof(message));
	readbuffer_ptr = readbuffer;
	readbuffer_length = ::strlen(message);

	int ret = init_http_connection(connection, &http_server, &br, false);
	BOOST_REQUIRE_MESSAGE(ret == 0, "Initialization failed for invalid start line!");
	BOOST_CHECK_MESSAGE(close_called, "Close was not called for invalid start_line");
	BOOST_CHECK_MESSAGE(check_http_response(404), "No \"Not found\" response if no URL handler matches!");
}

BOOST_FIXTURE_TEST_CASE(test_read_valid_startline_invalid_url, F)
{
	const char message[] = "GET http://ww%.google.de/ HTTP/1.1\r\n";
	::memcpy(readbuffer, message, sizeof(message));
	readbuffer_ptr = readbuffer;
	readbuffer_length = ::strlen(message);

	int ret = init_http_connection(connection, &http_server, &br, false);
	BOOST_REQUIRE_MESSAGE(ret == 0, "Initialization failed for invalid URL!");
	BOOST_CHECK_MESSAGE(close_called, "Close was not called for invalid URL!");
	BOOST_CHECK_MESSAGE(check_http_response(400), "No \"bad request\" response for invalid URL!");
}

BOOST_FIXTURE_TEST_CASE(test_read_valid_startline_connect_request_url_match, F)
{
	const char message[] = "CONNECT www.example.com:443 HTTP/1.1\r\n";
	::memcpy(readbuffer, message, sizeof(message));
	readbuffer_ptr = readbuffer;
	readbuffer_length = ::strlen(message);

	int ret = init_http_connection(connection, &http_server, &br, false);
	BOOST_REQUIRE_MESSAGE(ret == 0, "Initialization failed for CONNECT http method!");
	BOOST_CHECK_MESSAGE(close_called, "Close was not called for CONNECT http method!");
	BOOST_CHECK_MESSAGE(check_http_response(400), "No \"bad request\" response for CONNECT http method!");
}
