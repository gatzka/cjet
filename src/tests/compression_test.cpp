/*
 * The MIT License (MIT)
 *
 * Copyright (c) <2017> <Felix Retsch>
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
#define BOOST_TEST_MODULE compression_tests

#include <boost/test/unit_test.hpp>
#include <stdio.h>

#include "compression.h"
#include "websocket.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

static const uint8_t FIN = 0x80;
static const uint8_t RSV1 = 0x40;
static const uint8_t TYPE_BINARY = 0x02;
static const uint8_t TYPE_PING = 0x09;

static bool text_correct = false;
static bool frame_correct = false;
static bool binary_correct = false;
static bool binary_frame_correct = false;
static bool got_error = false;
static uint8_t *read_buffer;
static uint8_t *read_buffer_ptr;
static size_t read_buffer_length;

char text[] = "Hello World! Hello World!";
const size_t text_length = 26;
uint8_t binary[text_length] = {0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21, 0x20,
                               0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21, 0x00};

static websocket_callback_return message_received(struct websocket *ws, char *msg, size_t length)
{
	(void)ws;
	(void)length;
	if (strcmp(msg, text) == 0) {
		text_correct = true;
	}
	return WS_OK;
}

static websocket_callback_return frame_received(struct websocket *ws, char *msg, size_t length, bool is_complete)
{
	(void)ws;
	(void)length;
	if (is_complete && (strcmp(msg, text) == 0)) {
		frame_correct = true;
	}
	return WS_OK;
}

static websocket_callback_return binary_received(struct websocket *ws, uint8_t *msg, size_t length)
{
	(void)ws;
	(void)length;
	if (memcmp(msg, binary, text_length) == 0) {
		binary_correct = true;
	}
	return WS_OK;
}

static websocket_callback_return binary_frame_received(struct websocket *ws, uint8_t *msg, size_t length, bool is_complete)
{
	(void)ws;
	(void)length;
	if (is_complete && (memcmp(msg, binary, text_length) == 0)) {
		binary_frame_correct = true;
	}
	return WS_OK;
}

static void ws_on_error(struct websocket *ws)
{
	(void)ws;
	got_error = true;
}

static int writev(void *this_ptr, struct socket_io_vector *io_vec, unsigned int count)
{
	(void)this_ptr;
	size_t complete_length = 0;

	for (unsigned int i = 0; i < count; i++) {
		complete_length += io_vec[i].iov_len;
	}
	return complete_length;
}

static int read_exactly(void *this_ptr, size_t num, read_handler handler, void *handler_context)
{
	(void)this_ptr;
	uint8_t *ptr = read_buffer_ptr;
	read_buffer_ptr += num;
	if ((ptr - read_buffer) < (cjet_ssize_t)read_buffer_length) {
		handler(handler_context, ptr, num);
	}
	return 0;
}

static int close(void *this_ptr)
{
	(void)this_ptr;
	return 0;
}

static void mask_payload(uint8_t *ptr, size_t length, uint8_t mask[4])
{
	for (unsigned int i = 0; i < length; i++) {
		uint8_t byte = ptr[i] ^ mask[i % 4];
		ptr[i] = byte;
	}
}

static void reset_extension_compression(struct websocket *ws)
{
	ws->extension_compression.accepted = false;
	ws->extension_compression.client_max_window_bits = 15;
	ws->extension_compression.client_no_context_takeover = false;
	ws->extension_compression.server_max_window_bits = 15;
	ws->extension_compression.server_no_context_takeover = false;
	ws->extension_compression.response[0] = 'u';
	ws->extension_compression.response[1] = 'n';
	ws->extension_compression.response[2] = 's';
	ws->extension_compression.response[3] = 'e';
	ws->extension_compression.response[4] = 't';
}

struct F {
	F ()
	{
		text_correct = false;
		frame_correct = false;
		binary_correct = false;
		binary_frame_correct = false;
		got_error = false;

		struct http_connection *connection = alloc_http_connection();
		connection->br.writev = writev;
		connection->br.read_exactly = read_exactly;
		connection->br.close = close;
		ws.protocol_requested = false;
		ws.binary_frame_received = NULL;
		ws.text_frame_received = NULL;
		ws.on_error = NULL;
		ws.connection = NULL;
		ws.length = 0;
		ws.ws_flags.fin = 0;
		ws.ws_flags.rsv = 0;
		ws.ws_flags.mask = 0;
		ws.ws_flags.opcode = 0;
		websocket_init(&ws, connection, true, ws_on_error, NULL);
		ws.upgrade_complete = true;
		alloc_compression(&ws);
		char response[] = "permessage-deflate";
		ws.extension_compression.response = (char *)::malloc(sizeof(response));
	}

	~F()
	{
//		if (ws.extension_compression.response != NULL) {
		if (!got_error) {
			free(ws.extension_compression.response);
			free_connection(ws.connection);
		}
		free_compression(&ws);
	}

	struct websocket ws;
};

BOOST_FIXTURE_TEST_CASE(test_comp_and_decomp_msg_simple, F)
{
	int have;
	uint8_t src[text_length];
	::memcpy(src,text, text_length);
	uint8_t dest[text_length*2];

	have = websocket_compress(&ws, dest, src, text_length);
	char dest_txt[have];
	::memcpy(dest_txt,dest,have);
	text_received_comp(true, &ws, dest_txt, have, message_received);
	BOOST_CHECK_MESSAGE(text_correct == true, "Received message differs from orginal!");
}

BOOST_FIXTURE_TEST_CASE(test_comp_and_decomp_msg_5_times, F)
{
	int have;
	uint8_t src [text_length];
	::memcpy(src,text, text_length);
	uint8_t dest[text_length*2];

	for(unsigned int i = 0; i < 5; i++) {
		have = websocket_compress(&ws, dest, src, text_length);
		char dest_txt[have];
		::memcpy(dest_txt,dest,have);
		text_received_comp(true, &ws, dest_txt, have, message_received);
		BOOST_CHECK_MESSAGE(text_correct == true, "Received message differs from orginal!");
		text_correct = false;
	}
}

BOOST_FIXTURE_TEST_CASE(test_comp_and_decomp_msg_frag, F)
{
	int have;
	websocket_callback_return ret;
	uint8_t src [text_length];
	::memcpy(src, text, text_length);
	uint8_t dest[text_length*2];

	have = websocket_compress(&ws, dest, src, text_length);
	char dest_txt[have];
	::memcpy(dest_txt, dest, have);
	size_t cut = have / 2;

	ret = text_frame_received_comp(true, &ws, dest_txt, cut, false, frame_received);
	BOOST_CHECK_MESSAGE(ret == WS_OK, "Problem with first fragment");

	ret = text_frame_received_comp(true, &ws, dest_txt + cut, have - cut, true, frame_received);
	BOOST_CHECK_MESSAGE(ret == WS_OK, "Error during decomp last fragment!");
	BOOST_CHECK_MESSAGE(frame_correct == true, "Received fragments differ from orginal!");
}

BOOST_FIXTURE_TEST_CASE(test_comp_and_decomp_binary_simple, F)
{
	int have;
	uint8_t dest[text_length*2];
	have = websocket_compress(&ws, dest, binary, text_length);
	binary_received_comp(true, &ws, dest, have, binary_received);
	BOOST_CHECK_MESSAGE(binary_correct == true, "Received binary differs from orginal!");
}

BOOST_FIXTURE_TEST_CASE(test_comp_and_decomp_binary_5_times, F)
{
	int have;
	uint8_t dest[text_length*2];

	for(unsigned int i = 0; i < 5; i++) {
		have = websocket_compress(&ws, dest, binary, text_length);
		binary_received_comp(true, &ws, dest, have, binary_received);
		BOOST_CHECK_MESSAGE(binary_correct == true, "Received binary differs from orginal!");
		binary_correct = false;
	}
}

BOOST_FIXTURE_TEST_CASE(test_comp_and_decomp_binary_frag, F)
{
	int have;
	websocket_callback_return ret;
	uint8_t dest[text_length*2];
	have = websocket_compress(&ws, dest, binary, text_length);
	size_t cut = have / 2;

	ret = binary_frame_received_comp(true, &ws, dest, cut, false, binary_frame_received);
	BOOST_CHECK_MESSAGE(ret == WS_OK, "Problem with first binary fragment");

	ret = binary_frame_received_comp(true, &ws, dest + cut, have - cut, true, binary_frame_received);
	BOOST_CHECK_MESSAGE(ret == WS_OK, "Error during decomp last binary fragment!");
	BOOST_CHECK_MESSAGE(binary_frame_correct == true, "Received binary fragments differ from orginal!");
}

BOOST_FIXTURE_TEST_CASE(test_compression_and_decompression_text_all_parameters,F)
{
	free_compression(&ws);

	int have;
	uint8_t src [text_length];
	::memcpy(src,text, text_length);
	uint8_t dest[text_length*2];

	for (unsigned int server_bits = 8; server_bits < 16; server_bits++) {
		ws.extension_compression.server_max_window_bits = server_bits;
		for (unsigned int client_bits = 8; client_bits < 16; client_bits++) {
			ws.extension_compression.client_max_window_bits = client_bits;
			for (unsigned int server_takeover = 0; server_takeover < 2; server_takeover++) {
				ws.extension_compression.server_no_context_takeover = server_takeover;
				for (unsigned int client_takeover = 0; client_takeover < 2; client_takeover++) {
					ws.extension_compression.client_no_context_takeover = client_takeover;
					alloc_compression(&ws);
					for(unsigned int i = 0; i < 5; i++) {
						have = websocket_compress(&ws, dest, src, text_length);
						char dest_txt[have];
						::memcpy(dest_txt,dest,have);
						text_received_comp(true, &ws, dest_txt, have, message_received);
						BOOST_CHECK_MESSAGE(text_correct == true, "Received message differs from orginal!");
						text_correct = false;
					}
					free_compression(&ws);
				}
			}
		}
	}

	alloc_compression(&ws);
}

BOOST_FIXTURE_TEST_CASE(test_rsv_bit_data_frame, F)
{
	ws.binary_message_received = binary_received;

	uint8_t dest[text_length*2];
	int have = websocket_compress(&ws, dest, binary, text_length);
	uint8_t mask[4] = {0xaa, 0x55, 0xcc, 0x11};
	mask_payload(dest, have, mask);

	read_buffer_length = 2 + sizeof(mask) + have;
	uint8_t readbuffer[read_buffer_length];
	readbuffer[0] = FIN | RSV1 | TYPE_BINARY;
	readbuffer[1] = 0x80 | ((uint8_t) have);
	::memcpy(readbuffer + 2, mask, 4);
	::memcpy(readbuffer + 6, dest, have);

	read_buffer = readbuffer;
	read_buffer_ptr = readbuffer +1;

	ws.extension_compression.accepted = true;
	readbuffer[0] = FIN | RSV1 | TYPE_BINARY;
	ws_get_header(&ws, read_buffer, read_buffer_length);
	BOOST_CHECK_MESSAGE(binary_correct, "Received message should be ok!");
	binary_correct = false;
	read_buffer = readbuffer;
	read_buffer_ptr = readbuffer + 1;

	ws.extension_compression.accepted = false;
	readbuffer[0] = FIN | RSV1 | TYPE_BINARY;
	ws_get_header(&ws, read_buffer_ptr, read_buffer_length);
	BOOST_CHECK_MESSAGE(got_error, "Error not called. RSV bit without compression is not allowed!");
}

BOOST_FIXTURE_TEST_CASE(test_rsv_bit_control_frame, F)
{
	ws.ping_received = binary_received;

	uint8_t mask[4] = {0xaa, 0x55, 0xcc, 0x11};
	read_buffer_length = 2 + sizeof(mask) + text_length;
	uint8_t readbuffer[read_buffer_length];
	readbuffer[1] = 0x80 | ((uint8_t) text_length);
	::memcpy(readbuffer + 2, mask, 4);
	::memcpy(readbuffer + 6, binary, text_length);
	mask_payload(readbuffer + 6, text_length, mask);

	read_buffer = readbuffer;
	read_buffer_ptr = readbuffer +1;

	ws.extension_compression.accepted = true;
	readbuffer[0] = FIN | TYPE_PING;
	ws_get_header(&ws, read_buffer, read_buffer_length);
	BOOST_CHECK_MESSAGE(binary_correct, "received message should be ok!");
	binary_correct = false;
	read_buffer = readbuffer;
	read_buffer_ptr = readbuffer + 1;

	readbuffer[0] = FIN | RSV1 | TYPE_PING;
	ws_get_header(&ws, read_buffer_ptr, read_buffer_length);
	BOOST_CHECK_MESSAGE(got_error, "Error not called. Compresed control frames are not allowed!");

}

BOOST_FIXTURE_TEST_CASE(test_parse_html_extension_field, F)
{
	http_parser parser;
	parser.data = &ws;
	ws.connection->parser = parser;
	unsigned int cases = 4;
	const char extension_line[cases][150] = {{"permessage-deflate"},
                                             {"permessage-deflate; client_max_window_bits=10; client_no_context_takeover;"
                                              " server_no_context_takeover; server_max_window_bits=10"},
                                             {"permessage-deflate; client_max_window_bits"},
                                             {"permessage-deflate; server_max_window_bits=8, permessage-deflate; server_max_window_bits=9"}};

	const char expected[cases][150] = {{"permessage-deflate"},
                                       {"permessage-deflate; client_max_window_bits=10; client_no_context_takeover;"
                                        " server_no_context_takeover; server_max_window_bits=10"},
                                       {"permessage-deflate; client_max_window_bits=15"},
                                       {"permessage-deflate; server_max_window_bits=9"}};
	size_t length;
	int ret;
	for (unsigned int i = 0; i < cases; i++) {
		free_compression(&ws);
		ws.current_header_field = HEADER_SEC_WEBSOCKET_EXTENSIONS;
		reset_extension_compression(&ws);
		length = strlen(extension_line[i]);
		websocket_upgrade_on_header_value(&parser, extension_line[i], length);
		ret = strcmp(ws.extension_compression.response, expected[i]);
		char str1[50];
		sprintf(str1, "Response should be equal to expected %d!", i);
		BOOST_CHECK_MESSAGE(ret == 0, str1);
		char str2[50];
		sprintf(str2, "Extension %d should be accpeted!", i);
		BOOST_CHECK_MESSAGE(ws.extension_compression.accepted, str2);
	}
}

BOOST_FIXTURE_TEST_CASE(test_parse_html_extension_field_illegal, F)
{
	http_parser parser;
	parser.data = &ws;
	ws.connection->parser = parser;
	unsigned int cases = 4;
	const char extension_line[cases][150]={{"permessage-deflate; server_max_window_bits=8"},
                                           {"permessage-deflate; client_no_context_takeover; client_no_context_takeover"},
                                           {"permessage-deflate; xxxxxxxxxxxxxxxxxxxxxxxxxx, client_no_context_takeover"},
                                           {"permeeeege-deeeeee; server_max_window_bits=10"}};
	size_t length;
	for (unsigned int i = 0; i < cases; i++) {
		ws.current_header_field = HEADER_SEC_WEBSOCKET_EXTENSIONS;
		reset_extension_compression(&ws);
		length = strlen(extension_line[i]);
		websocket_upgrade_on_header_value(&parser, extension_line[i], length);
		char str[50];
		sprintf(str, "Extension %d should not be accpeted!", i);
		BOOST_CHECK_MESSAGE(!ws.extension_compression.accepted, str);
	}
}
