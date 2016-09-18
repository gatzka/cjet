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
#include <endian.h>
#include <cstdint>

#include "buffered_reader.h"
#include "http_connection.h"
#include "websocket.h"

#ifndef ARRAY_SIZE
 #define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

static const uint8_t WS_HEADER_FIN = 0x80;
static const uint8_t WS_HEADER_MASK = 0x80;
static const uint8_t WS_OPCODE_CLOSE = 0x08;

static uint8_t write_buffer[5000];
static uint8_t *write_buffer_ptr;

static bool close_called;

static void ws_on_error(struct websocket *ws)
{
	(void)ws;
}


static int writev(void *this_ptr, struct buffered_socket_io_vector *io_vec, unsigned int count)
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

static bool is_close_frame()
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
	if (status_code != 1001) {
		return false;
	}
	return true;
}

static int close(void *this_ptr)
{
	(void)this_ptr;
	close_called = true;
	return 0;
}

struct F {

	F()
	{
		close_called = false;
		write_buffer_ptr = write_buffer;

		struct http_connection *connection = alloc_http_connection();
		connection->br.writev = writev;
		connection->br.close = close;
		websocket_init(&ws, connection, true, ws_on_error, "jet");
		ws.upgrade_complete = true;
	}

	~F()
	{
	}

	struct websocket ws;
};

BOOST_FIXTURE_TEST_CASE(test_close_frame_on_websocket_free, F)
{
	websocket_free(&ws);
	BOOST_CHECK_MESSAGE(is_close_frame(), "No close frame sent when freeing the websocket!");
}

