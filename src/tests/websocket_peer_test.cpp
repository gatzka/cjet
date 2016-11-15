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

static const uint8_t WS_HEADER_FIN = 0x80;
static const uint8_t WS_HEADER_MASK = 0x80;

static const uint8_t WS_OPCODE_CLOSE = 0x08;
static const uint8_t WS_OPCODE_ILLEGAL = 0x0b;

static unsigned int num_close_called = 0;
static uint8_t read_buffer[5000];
static size_t read_buffer_length;
static uint8_t *read_buffer_ptr;

static uint8_t write_buffer[70000];
static uint8_t *write_buffer_ptr;
static error_handler br_error_handler = NULL;
static void *br_error_context = NULL;

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
		uint8_t *ptr = read_buffer_ptr;
		read_buffer_ptr += num;
		if ((ptr - read_buffer) < (ssize_t)read_buffer_length) {
			handler(handler_context, ptr, num);
		}
		return 0;
	}

	static int br_read_until(void *this_ptr, const char *delim, read_handler handler, void *handler_context) {
		(void)this_ptr;
		(void)delim;
		(void)handler;
		(void)handler_context;
		return 0;
	}

	static int br_writev(void *this_ptr, struct socket_io_vector *io_vec, unsigned int count)
	{
		(void)this_ptr;
		size_t complete_length = 0;

		for (unsigned int i = 0; i < count; i++) {
			::memcpy(write_buffer_ptr, io_vec[i].iov_base, io_vec[i].iov_len);
			write_buffer_ptr += io_vec[i].iov_len;
			complete_length += io_vec[i].iov_len;
		}
		return complete_length;
	}


	static int br_close(void *this_ptr) {
		(void)this_ptr;
		num_close_called++;
		return 0;
	}

	static void br_set_error_handler(void *this_ptr, error_handler handler, void *error_context) {
		(void)this_ptr;
		br_error_handler = handler;
		br_error_context = error_context;
		return;
	}
}

struct F {

	F()
	{
		num_close_called = 0;
		write_buffer_ptr = write_buffer;

		read_buffer_ptr = read_buffer;

		br.this_ptr = NULL;
		br.close = br_close;
		br.read_exactly = br_read_exactly;
		br.read_until = br_read_until;
		br.set_error_handler = br_set_error_handler;
		br.writev = br_writev;
	}

	~F()
	{
	}

	struct buffered_reader br;
};

static void mask_payload(uint8_t *ptr, size_t length, uint8_t mask[4])
{
	for (unsigned int i = 0; i < length; i++) {
		uint8_t byte = ptr[i] ^ mask[i % 4];
		ptr[i] = byte;
	}
}

static void fill_payload(uint8_t *ptr, const uint8_t *payload, uint64_t length, bool shall_mask, uint8_t mask[4])
{
	::memcpy(ptr, payload, length);
	if (shall_mask) {
		mask_payload(ptr, length, mask);
	}
}

static void prepare_message(uint8_t type, uint8_t *buffer, uint64_t length, bool shall_mask, uint8_t mask[4])
{
	uint8_t *ptr = read_buffer;
	read_buffer_length = 0;
	uint8_t header = 0x00;
	header |= WS_HEADER_FIN;
	header |= type;
	::memcpy(ptr, &header, sizeof(header));
	ptr += sizeof(header);
	read_buffer_length += sizeof(header);

	uint8_t first_length = 0x00;
	if (shall_mask) {
		first_length |= WS_HEADER_MASK;
	}
	if (length < 126) {
		first_length = first_length | (uint8_t)length;
		::memcpy(ptr, &first_length, sizeof(first_length));
		ptr += sizeof(first_length);
		read_buffer_length += sizeof(first_length);
	} else if (length <= 65535) {
		first_length = first_length | 126;
		::memcpy(ptr, &first_length, sizeof(first_length));
		ptr += sizeof(first_length);
		read_buffer_length += sizeof(first_length);
		uint16_t len = (uint16_t)length;
		len = htobe16(len);
		::memcpy(ptr, &len, sizeof(len));
		ptr += sizeof(len);
		read_buffer_length += sizeof(len);
	} else {
		first_length = first_length | 127;
		::memcpy(ptr, &first_length, sizeof(first_length));
		ptr += sizeof(first_length);
		read_buffer_length += sizeof(first_length);
		uint64_t len = htobe64(length);
		::memcpy(ptr, &len, sizeof(length));
		ptr += sizeof(len);
		read_buffer_length += sizeof(len);
	}

	if (shall_mask) {
		::memcpy(ptr, mask, 4);
		ptr += 4;
		read_buffer_length += 4;
	}

	fill_payload(ptr, buffer, length, shall_mask, mask);
	read_buffer_length += length;
}

static bool is_close_frame(enum ws_status_code code)
{
	const uint8_t *ptr = write_buffer;
	uint8_t header;
	::memcpy(&header, ptr, sizeof(header));
	if ((header & WS_HEADER_FIN) != WS_HEADER_FIN) {
		return false;
	}
	if ((header & WS_OPCODE_CLOSE) != WS_OPCODE_CLOSE) {
		return false;
	}
	ptr += sizeof(header);

	uint8_t length;
	::memcpy(&length, ptr, sizeof(length));
	if ((length & WS_HEADER_MASK) == WS_HEADER_MASK) {
		return false;
	}
	if (length != 2) {
		return false;
	}
	ptr += sizeof(length);

	uint16_t status_code;
	::memcpy(&status_code, ptr, sizeof(status_code));
	status_code = be16toh(status_code);
	if (status_code != code) {
		return false;
	}
	return true;
}

BOOST_AUTO_TEST_CASE(test_connection_closed_when_destryoing_peers)
{
	F f;

	struct http_server server;
	server.ev.loop = NULL;

	struct http_connection *connection = alloc_http_connection();
	init_http_connection(connection, &server, &f.br, false);

	int ret = alloc_websocket_peer(connection);
	BOOST_REQUIRE_MESSAGE(ret == 0, "alloc_websocket_peer did not return 0");

	struct websocket *socket = (struct websocket *)connection->parser.data;
	socket->upgrade_complete = true;

	destroy_all_peers();
	BOOST_CHECK_MESSAGE(num_close_called == 1, "Close of buffered_reader was not called when destryoing all peers!");
	BOOST_CHECK_MESSAGE(is_close_frame(WS_CLOSE_GOING_AWAY), "No close frame sent when destryoing all peers!");
}

BOOST_AUTO_TEST_CASE(test_connection_closed_when_buffered_reader_gots_error)
{
	F f;

	struct http_server server;
	server.ev.loop = NULL;

	struct http_connection *connection = alloc_http_connection();
	init_http_connection(connection, &server, &f.br, false);

	int ret = alloc_websocket_peer(connection);
	BOOST_REQUIRE_MESSAGE(ret == 0, "alloc_websocket_peer did not return 0");

	struct websocket *socket = (struct websocket *)connection->parser.data;
	socket->upgrade_complete = true;
	br_error_handler(br_error_context);

	BOOST_CHECK_MESSAGE(num_close_called == 1, "Close of buffered_reader was not called when buffered_reader has an error!");
	BOOST_CHECK_MESSAGE(is_close_frame(WS_CLOSE_GOING_AWAY), "No close frame sent when bufferd_reader has an error!");
}

BOOST_AUTO_TEST_CASE(test_connection_closed_when_receiving_fin)
{
	F f;

	struct http_server server;
	server.ev.loop = NULL;

	struct http_connection *connection = alloc_http_connection();
	init_http_connection(connection, &server, &f.br, false);

	int ret = alloc_websocket_peer(connection);
	BOOST_REQUIRE_MESSAGE(ret == 0, "alloc_websocket_peer did not return 0");

	struct websocket *socket = (struct websocket *)connection->parser.data;
	socket->upgrade_complete = true;

	uint8_t mask[4] = {0xaa, 0x55, 0xcc, 0x11};
	prepare_message(WS_OPCODE_CLOSE, NULL, 0, true, mask);
	ws_get_header(socket, read_buffer_ptr++, read_buffer_length);

	BOOST_CHECK_MESSAGE(num_close_called == 1, "Close of buffered_reader was not called when receiving a close frame!");
	BOOST_CHECK_MESSAGE(is_close_frame(WS_CLOSE_GOING_AWAY), "No close frame sent when receiving a close frame!");
}

BOOST_AUTO_TEST_CASE(test_connection_closed_when_illegal_message)
{
	F f;

	struct http_server server;
	server.ev.loop = NULL;

	struct http_connection *connection = alloc_http_connection();
	init_http_connection(connection, &server, &f.br, false);

	int ret = alloc_websocket_peer(connection);
	BOOST_REQUIRE_MESSAGE(ret == 0, "alloc_websocket_peer did not return 0");

	struct websocket *socket = (struct websocket *)connection->parser.data;
	socket->upgrade_complete = true;

	uint8_t mask[4] = {0xaa, 0x55, 0xcc, 0x11};
	prepare_message(WS_OPCODE_ILLEGAL, NULL, 0, true, mask);
	ws_get_header(socket, read_buffer_ptr++, read_buffer_length);

	BOOST_CHECK_MESSAGE(num_close_called == 1, "Close of buffered_reader was not called when receiving an illegal frame!");
	BOOST_CHECK_MESSAGE(is_close_frame(WS_CLOSE_UNSUPPORTED), "No close frame sent when receiving an illegal frame!");
}
