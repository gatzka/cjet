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

#include "jet_string.h"
#include "socket.h"
#include "websocket.h"

#define CRLF "\r\n"

#ifndef ARRAY_SIZE
 #define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

static const int FD_CORRECT_UPGRADE = 1;
static bool ws_error = false;

static const char *readbuffer;
static const char *readbuffer_ptr;

static http_parser response_parser;
static http_parser_settings response_parser_settings;
static bool got_complete_response_header = false;
static bool response_parse_error = false;

extern "C" {
	ssize_t socket_writev(socket_type sock, struct buffered_socket_io_vector *io_vec, unsigned int count)
	{
		switch (sock) {
		case FD_CORRECT_UPGRADE: {
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
					
				}
				complete_length += io_vec[i].iov_len;
			}
			return complete_length;
		}
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

static enum callback_return eventloop_fake_add(const void *this_ptr, const struct io_event *ev)
{
	(void)this_ptr;
	(void)ev;
	return CONTINUE_LOOP;
}

static void eventloop_fake_remove(const void *this_ptr, const struct io_event *ev)
{
	(void)this_ptr;
	(void)ev;
}

static void ws_on_error(struct websocket *ws)
{
	(void)ws;
	ws_error = true;
}

static int on_headers_complete(http_parser *parser)
{
	(void)parser;
	got_complete_response_header = true;
	return 0;
}

struct F {
	
	enum response_on_header_field {
		HEADER_UNKNOWN,
		HEADER_UPGRADE,
		HEADER_CONNECTION,
		HEADER_ACCEPT,
	};

	F()
	{
		loop.init = NULL;
		loop.destroy = NULL;
		loop.run = NULL;
		loop.add = eventloop_fake_add;
		loop.remove = eventloop_fake_remove;
		
		readbuffer_ptr = readbuffer;
		got_complete_response_header = false;
		response_parse_error = false;

		http_parser_settings_init(&parser_settings);
		http_parser_init(&parser, HTTP_REQUEST);

		http_parser_settings_init(&response_parser_settings);
		http_parser_init(&response_parser, HTTP_RESPONSE);
		response_parser.data = this;
		response_parser_settings.on_header_field = response_on_header_field;
		response_parser_settings.on_header_value = response_on_header_value;
		response_parser_settings.on_headers_complete = on_headers_complete;

		handler[0].request_target = "/";
		handler[0].create = NULL;
		
		handler[0].on_header_field = websocket_upgrade_on_header_field,
		handler[0].on_header_value = websocket_upgrade_on_header_value,
		handler[0].on_headers_complete = websocket_upgrade_on_headers_complete,
		handler[0].on_body = NULL;
		handler[0].on_message_complete = NULL;

		http_server.handler = handler;
		http_server.num_handlers = ARRAY_SIZE(handler);

		::memset(websocket_accept_key, 0, sizeof(websocket_accept_key));

		ws_error = false;
		got_upgrade_response = false;
		got_connection_upgrade = false;
		current_header_field = HEADER_UNKNOWN;
	}

	~F()
	{
	}

	static int response_on_header_field(http_parser *p, const char *at, size_t length)
	{
		struct F *f = (struct F *)p->data;

		static const char upgrade_key[] = "Upgrade";
		if ((sizeof(upgrade_key) - 1  == length) && (jet_strncasecmp(at, upgrade_key, length) == 0)) {
			f->current_header_field = HEADER_UPGRADE;
			return 0;
		}

		static const char connection_key[] = "Connection";
		if ((sizeof(connection_key) - 1  == length) && (jet_strncasecmp(at, connection_key, length) == 0)) {
			f->current_header_field = HEADER_CONNECTION;
			return 0;
		}

		static const char accept_key[] = "Sec-WebSocket-Accept";
		if ((sizeof(accept_key) - 1  == length) && (jet_strncasecmp(at, accept_key, length) == 0)) {
			f->current_header_field = HEADER_ACCEPT;
			return 0;
		}
		return 0;
	}

	static int response_on_header_value(http_parser *p, const char *at, size_t length)
	{
		int ret = 0;
		struct F *f = (struct F *)p->data;
		switch(f->current_header_field) {
		case HEADER_UPGRADE:
			f->got_upgrade_response = true;
			break;

		case HEADER_CONNECTION:
			if (jet_strncasecmp(at, "Upgrade", length) == 0) {
				f->got_connection_upgrade = true;
			}
			break;

		case HEADER_ACCEPT: {
			size_t len = std::min(length, sizeof(websocket_accept_key));
			memcpy(f->websocket_accept_key, at, len);
			break;
		}

		case HEADER_UNKNOWN:
		default:
			break;
		}

		f->current_header_field = HEADER_UNKNOWN;
		return ret;
	}

	struct eventloop loop;
	http_parser parser;
	http_parser_settings parser_settings;
	struct url_handler handler[1];
	struct http_server http_server;

	bool got_upgrade_response;
	bool got_connection_upgrade;
	enum response_on_header_field current_header_field;
	uint8_t websocket_accept_key[28];
};

BOOST_AUTO_TEST_CASE(test_websocket_init)
{
	struct websocket ws;
	websocket_init(&ws, NULL, true, NULL);
	websocket_free(&ws);
}

BOOST_FIXTURE_TEST_CASE(test_http_upgrade, F)
{
	char request[] = "GET / HTTP/1.1" CRLF
	                 "Connection: Upgrade" CRLF \
	                 "Upgrade: websocket" CRLF \
	                 "Sec-WebSocket-Version: 13" CRLF\
	                 "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" CRLF CRLF;

	struct http_connection *connection = alloc_http_connection(&http_server, &loop, FD_CORRECT_UPGRADE);
	BOOST_REQUIRE_MESSAGE(connection != NULL, "Failed to allocate http connection");

	struct websocket ws;
	websocket_init(&ws, connection, true, ws_on_error);
	connection->parser.data = &ws;

	bs_read_callback_return ret = websocket_read_header_line(&ws, request, ::strlen(request));
	BOOST_CHECK_MESSAGE(ret == BS_OK, "websocket_read_header_line did not return BS_OK");
	BOOST_CHECK_MESSAGE(ws_error == false, "Error while parsing the http upgrade request");
	websocket_free(&ws);

	BOOST_CHECK_MESSAGE(response_parser.status_code == 101, "Expected 101 status code");
	BOOST_CHECK_MESSAGE(response_parser.http_major == 1, "Expected http major 1");
	BOOST_CHECK_MESSAGE(response_parser.http_minor == 1, "Expected http minor 1");
	BOOST_CHECK_MESSAGE(response_parse_error == false, "Invalid upgrade response!");
	BOOST_CHECK_MESSAGE(got_upgrade_response == true, "Upgrade header field missing!");
	BOOST_CHECK_MESSAGE(got_connection_upgrade == true, "Connection header field missing!");
	BOOST_CHECK_MESSAGE(::memcmp(websocket_accept_key, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", sizeof(websocket_accept_key)) == 0, "Got illegal websocket accept key!");

	// TODO: Check that close frame was sent
}
