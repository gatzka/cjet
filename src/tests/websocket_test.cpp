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
#include "jet_endian.h"
#include "jet_string.h"
#include "socket.h"
#include "websocket.h"

#define CRLF "\r\n"

#ifndef ARRAY_SIZE
 #define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

static const size_t websocket_accept_key_length = 28;

enum fds {
	FD_CORRECT_UPGRADE,
	FD_CLOSE_WHILE_READING,
};

static bool ws_error = false;

static const char *readbuffer;
static const char *readbuffer_ptr;

static int read_called = 0;

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

		write_buffer_ptr = write_buffer;

		ws_error = false;
		got_upgrade_response = false;
		got_connection_upgrade = false;
		current_header_field = HEADER_UNKNOWN;

		read_called = 0;

		connection = alloc_http_connection();
		bs = buffered_socket_acquire();
		buffered_socket_init(bs, 0, &loop, NULL, NULL);
		br.this_ptr = bs;
		br.close = buffered_socket_close;
		br.read_exactly = buffered_socket_read_exactly;
		br.read_until = buffered_socket_read_until;
		br.set_error_handler = buffered_socket_set_error;
		br.writev = buffered_socket_writev;
		init_http_connection(connection, &http_server, &br,false);

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
			size_t len = std::min(length, websocket_accept_key_length);
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
	uint8_t websocket_accept_key[websocket_accept_key_length];

	struct http_connection *connection;
	struct buffered_socket *bs;
	struct buffered_reader br;
};

static const uint8_t WS_HEADER_FIN = 0x80;
static const uint8_t WS_CLOSE_FRAME = 0x08;
static const uint8_t WS_MASK_BIT = 0x80;
static const uint8_t WS_PAYLOAD_LENGTH = 0x7f;

static bool is_close_frame()
{
	if ((write_buffer[0] & WS_HEADER_FIN) == 0) {
		return false;
	}

	if ((write_buffer[0] & WS_CLOSE_FRAME) == 0) {
		return false;
	}

	if ((write_buffer[1] & WS_MASK_BIT) != 0) {
		return false;
	}

	size_t len = write_buffer[1] & WS_PAYLOAD_LENGTH;
	if (len < 2) {
		return false;
	}

	uint16_t status_code;
	::memcpy(&status_code, &write_buffer[2], sizeof(status_code));
	status_code = jet_be16toh(status_code);
	if (status_code != 1001) {
		return false;
	}

	return true;
}

BOOST_FIXTURE_TEST_CASE(test_websocket_init, F)
{
	struct websocket ws;
	int ret = websocket_init(&ws, connection, true, ws_on_error, "soap");
	BOOST_CHECK_MESSAGE(ret == 0, "Initializaton of websocket failed!");
	websocket_free(&ws, 1001);
}

BOOST_AUTO_TEST_CASE(test_websocket_init_without_error_callback)
{
	struct websocket ws;
	int ret = websocket_init(&ws, NULL, true, NULL, "soap");
	BOOST_CHECK_MESSAGE(ret == -1, "Initializaton of websocket did not failed when called without error function!");
}

BOOST_AUTO_TEST_CASE(test_websocket_init_without_subprotocols)
{
	struct websocket ws;
	int ret = websocket_init(&ws, NULL, true, ws_on_error, NULL);
	BOOST_CHECK_MESSAGE(ret == -1, "Initializaton of websocket did not failed when called without supported sub-protocol!");
}

BOOST_FIXTURE_TEST_CASE(http_upgrade_with_websocket_protocol, F)
{
	const char *sub_protocols[2] = {"jet", "chat"};

	std::string request(
		"GET / HTTP/1.1" CRLF
		"Connection: Upgrade" CRLF
		"Upgrade: websocket" CRLF
		"Sec-WebSocket-Protocol: ");
	for (unsigned int i = 0; i < ARRAY_SIZE(sub_protocols); i++) {
		request.append(sub_protocols[i]);
		if (i != ARRAY_SIZE(sub_protocols) - 1) {
			request.append(", ");
		}
	}
	request.append(
		CRLF
		"Sec-WebSocket-Version: 13" CRLF
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" CRLF CRLF);
	std::vector<char> data(request.begin(), request.end());

	struct websocket ws;
	BOOST_REQUIRE_MESSAGE(websocket_init(&ws, connection, true, ws_on_error, "jet") == 0, "Websocket initialization failed!");
	connection->parser.data = &ws;

	bs_read_callback_return ret = websocket_read_header_line(&ws, (uint8_t *)&data[0], data.size());
	BOOST_CHECK_MESSAGE(ret == BS_OK, "websocket_read_header_line did not return expected return value");
	websocket_free(&ws, 1001);
	if (ret == BS_OK) {
		BOOST_CHECK_MESSAGE(ws_error == false, "Got error while parsing response for correct upgrade request");
		BOOST_CHECK_MESSAGE(response_parser.status_code == 101, "Expected 101 status code");
		BOOST_CHECK_MESSAGE(response_parser.http_major == 1, "Expected http major 1");
		BOOST_CHECK_MESSAGE(response_parser.http_minor == 1, "Expected http minor 1");
		BOOST_CHECK_MESSAGE(response_parse_error == false, "Invalid upgrade response!");
		BOOST_CHECK_MESSAGE(got_upgrade_response == true, "Upgrade header field missing!");
		BOOST_CHECK_MESSAGE(got_connection_upgrade == true, "Connection header field missing!");
		BOOST_CHECK_MESSAGE(::memcmp(websocket_accept_key, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", sizeof(websocket_accept_key)) == 0, "Got illegal websocket accept key!");
		BOOST_CHECK_MESSAGE(is_close_frame(), "No close frame sent!");
	}
}

BOOST_FIXTURE_TEST_CASE(http_upgrade_with_illegal_websocket_key, F)
{
	const char *sub_protocols[2] = {"jet", "chat"};

	std::string request(
		"GET / HTTP/1.1" CRLF
		"Connection: Upgrade" CRLF
		"Upgrade: websocket" CRLF
		"Sec-WebSocket-Protocol: ");
	for (unsigned int i = 0; i < ARRAY_SIZE(sub_protocols); i++) {
		request.append(sub_protocols[i]);
		if (i != ARRAY_SIZE(sub_protocols) - 1) {
			request.append(", ");
		}
	}
	request.append(
		CRLF
		"Sec-WebSocket-Version: 13" CRLF
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub2" CRLF CRLF);
	std::vector<char> data(request.begin(), request.end());

	struct websocket ws;
	BOOST_REQUIRE_MESSAGE(websocket_init(&ws, connection, true, ws_on_error, "jet") == 0, "Websocket initialization failed!");
	connection->parser.data = &ws;

	bs_read_callback_return ret = websocket_read_header_line(&ws, (uint8_t *)&data[0], data.size());
	BOOST_CHECK_MESSAGE(ret == BS_CLOSED, "websocket was not closed when illegal WebSocketKey was provided!");
}

BOOST_FIXTURE_TEST_CASE(http_upgrade_with_unsupported_websocket_protocol, F)
{
	const char *sub_protocols[2] = {"wamp", "chat"};

	std::string request(
		"GET / HTTP/1.1" CRLF
		"Connection: Upgrade" CRLF
		"Upgrade: websocket" CRLF
		"Sec-WebSocket-Protocol: ");
	for (unsigned int i = 0; i < ARRAY_SIZE(sub_protocols); i++) {
		request.append(sub_protocols[i]);
		if (i != ARRAY_SIZE(sub_protocols) - 1) {
			request.append(", ");
		}
	}
	request.append(
		CRLF
		"Sec-WebSocket-Version: 13" CRLF
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" CRLF CRLF);
	std::vector<char> data(request.begin(), request.end());

	struct websocket ws;
	BOOST_REQUIRE_MESSAGE(websocket_init(&ws, connection, true, ws_on_error, "jet") == 0, "Websocket initialization failed!");
	connection->parser.data = &ws;

	bs_read_callback_return ret = websocket_read_header_line(&ws, (uint8_t *)&data[0], data.size());
	BOOST_CHECK_MESSAGE(ret == BS_CLOSED, "websocket was not closed when websocket upgrade contains only unsupported sub protocols");
	BOOST_CHECK_MESSAGE(ws_error == true, "on_error function was not called when websocket upgrade contains only unsupported sub protocols");
}

BOOST_AUTO_TEST_CASE(test_http_upgrade_http_version)
{
	struct entry {
		const char *version;
		bs_read_callback_return expected_return;
	};

	struct entry table[] = {
		{"", BS_CLOSED},
		{"HTTP/0.1", BS_CLOSED},
		{"HTTP/0.9", BS_CLOSED},
		{"HTTP/1.0", BS_CLOSED},
		{"HTTP/1.1", BS_OK},
		{"HTTP/1.2", BS_OK},
		{"HTTP/2.0", BS_OK},
		{"HTTP/2.1", BS_OK},
	};

	for (unsigned int i = 0; i < ARRAY_SIZE(table); ++i) {
		F f;
		std::string request;
		request.append("GET / ");
		request.append(table[i].version);
		request.append(CRLF "Connection: Upgrade" CRLF "Upgrade: websocket" CRLF "Sec-WebSocket-Version: 13" CRLF "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" CRLF CRLF);
		std::vector<char> data(request.begin(), request.end());

		struct websocket ws;
		BOOST_REQUIRE_MESSAGE(websocket_init(&ws, f.connection, true, ws_on_error, "chat") == 0, "Websocket initialization failed!");
		f.connection->parser.data = &ws;
		
		bs_read_callback_return ret = websocket_read_header_line(&ws, (uint8_t *)&data[0], data.size());
		BOOST_CHECK_MESSAGE(ret == table[i].expected_return, "websocket_read_header_line did not return expected return value");
		if (ret == BS_OK) {
			websocket_free(&ws, 1001);
			BOOST_CHECK_MESSAGE(ws_error == false, "Got error while parsing response for correct upgrade request");
			BOOST_CHECK_MESSAGE(response_parser.status_code == 101, "Expected 101 status code");
			BOOST_CHECK_MESSAGE(response_parser.http_major == 1, "Expected http major 1");
			BOOST_CHECK_MESSAGE(response_parser.http_minor == 1, "Expected http minor 1");
			BOOST_CHECK_MESSAGE(response_parse_error == false, "Invalid upgrade response!");
			BOOST_CHECK_MESSAGE(f.got_upgrade_response == true, "Upgrade header field missing!");
			BOOST_CHECK_MESSAGE(f.got_connection_upgrade == true, "Connection header field missing!");
			BOOST_CHECK_MESSAGE(::memcmp(f.websocket_accept_key, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", sizeof(f.websocket_accept_key)) == 0, "Got illegal websocket accept key!");
			BOOST_CHECK_MESSAGE(is_close_frame(), "No close frame sent!");
		} else {
			BOOST_CHECK_MESSAGE(ws_error == true, "Wrong HTTP version accepted!");
		}
	}
}

BOOST_AUTO_TEST_CASE(test_http_upgrade_wrong_ws_version)
{
	struct entry {
		const char *version;
		bs_read_callback_return expected_return;
	};

	struct entry table[] = {
		{"13", BS_OK},
		{"-1", BS_CLOSED},
		{"0", BS_CLOSED},
	};

	for (unsigned int i = 0; i < ARRAY_SIZE(table); ++i) {
		F f;
		std::string request;
		request.append("GET / HTTP/1.1" CRLF "Connection: Upgrade" CRLF "Upgrade: websocket" CRLF "Sec-WebSocket-Version: ");
		request.append(table[i].version);
		request.append(CRLF "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" CRLF CRLF);
		std::vector<char> data(request.begin(), request.end());

		struct websocket ws;
		BOOST_REQUIRE_MESSAGE(websocket_init(&ws, f.connection, true, ws_on_error, "soap") == 0, "Websocket initialization failed!");
		f.connection->parser.data = &ws;

		bs_read_callback_return ret = websocket_read_header_line(&ws, (uint8_t *)&data[0], data.size());
		BOOST_CHECK_MESSAGE(ret == table[i].expected_return, "websocket_read_header_line did not return expected return value");
		if (ret == BS_OK) {
			websocket_free(&ws, 1001);
			BOOST_CHECK_MESSAGE(ws_error == false, "Got error while parsing response for correct upgrade request");
		} else {
			BOOST_CHECK_MESSAGE(ws_error == true, "Wrong websocket version accepted!");
		}
	}
}

BOOST_AUTO_TEST_CASE(test_http_upgrade_wrong_http_method)
{
	struct entry {
		const char *method;
		bs_read_callback_return expected_return;
	};

	struct entry table[] = {
		{"GET", BS_OK},
		{"GETT", BS_CLOSED},
		{"POST", BS_CLOSED},
		{"PUT", BS_CLOSED},
	};

	for (unsigned int i = 0; i < ARRAY_SIZE(table); ++i) {
		F f;
		std::string request;
		request.append(table[i].method);
		request.append(" / HTTP/1.1" CRLF "Connection: Upgrade" CRLF "Upgrade: websocket" CRLF "Sec-WebSocket-Version: 13" CRLF "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" CRLF CRLF);
		std::vector<char> data(request.begin(), request.end());

		struct websocket ws;
		BOOST_REQUIRE_MESSAGE(websocket_init(&ws, f.connection, true, ws_on_error, "json") == 0, "Websocket initialization failed!");
		f.connection->parser.data = &ws;

		bs_read_callback_return ret = websocket_read_header_line(&ws, (uint8_t *)&data[0], data.size());
		BOOST_CHECK_MESSAGE(ret == table[i].expected_return, "websocket_read_header_line did not return expected return value");
		if (ret == BS_OK) {
			BOOST_CHECK_MESSAGE(ws_error == false, "Got error while parsing response for correct upgrade request");
			websocket_free(&ws, 1001);
		} else {
			BOOST_CHECK_MESSAGE(ws_error == true, "Illegal http method accepted!");
		}
	}
}

BOOST_FIXTURE_TEST_CASE(test_http_only_header_parts, F)
{
	std::string request;
	request.append("GET / HTTP/1.1" CRLF "Connection: Upgrade" CRLF "Upgrade: websocket" CRLF "Sec-WebSocket-Version: 13" CRLF);
	std::vector<char> data(request.begin(), request.end());

	struct websocket ws;
	BOOST_REQUIRE_MESSAGE(websocket_init(&ws, connection, true, ws_on_error, "wamp") == 0, "Websocket initialization failed!");
	connection->parser.data = &ws;

	bs_read_callback_return ret = websocket_read_header_line(&ws, (uint8_t *)&data[0], data.size());
	BOOST_CHECK_MESSAGE(ret == BS_OK, "websocket_read_header_line did not return expected return value");
	websocket_free(&ws, 1001);
}

BOOST_FIXTURE_TEST_CASE(test_close_while_reading_http_headers, F)
{
	struct websocket ws;
	BOOST_REQUIRE_MESSAGE(websocket_init(&ws, connection, true, ws_on_error, "wamp") == 0, "Websocket initialization failed!");
	connection->parser.data = &ws;

	bs_read_callback_return ret = websocket_read_header_line(&ws, NULL, 0);
	BOOST_CHECK_MESSAGE(ret == BS_CLOSED, "websocket_read_header_line did not return expected return value");
	BOOST_CHECK_MESSAGE(ws_error, "error function was not called socket was closed during header read!");
}
