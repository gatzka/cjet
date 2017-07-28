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
static const uint8_t TYPE_CONTINUATION = 0x00;
static const uint8_t TYPE_BINARY = 0x02;
static const uint8_t TYPE_PING = 0x09;
static const unsigned int MAX_COMP_LEVEL = 3;

static bool text_correct = false;
static bool frame_correct = false;
static bool binary_correct = false;
static bool binary_frame_correct = false;
static bool got_error = false;
static uint8_t *read_buffer_start;
static uint8_t *read_buffer_ptr;
static size_t read_buffer_length;
static uint8_t *fragmentation_buffer;
static uint8_t *fragmentation_buffer_ptr;
static unsigned int param_val_comp_level[MAX_COMP_LEVEL + 1][4];	//0 cmw, 1 cnc, 2 smw, 3 snc
static int max_window_val_c_s[4][2];	//[case][client, server]

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
	::memcpy(fragmentation_buffer_ptr, msg, length);
	fragmentation_buffer_ptr += length;
	if (is_complete && (strcmp((char *)fragmentation_buffer, text) == 0)) {
		fragmentation_buffer_ptr = fragmentation_buffer;
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
	::memcpy(fragmentation_buffer_ptr, msg, length);
	fragmentation_buffer_ptr += length;
	if (is_complete && (memcmp(fragmentation_buffer, binary, text_length) == 0)) {
		fragmentation_buffer_ptr = fragmentation_buffer;
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
	if ((ptr - read_buffer_start) < (cjet_ssize_t)read_buffer_length) {
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

/*
 * stores the default parameter values for each compression level
 * to param_val_comp_level[level][parameter_no]
 */
static void fill_param_values()
{
	struct websocket ws;
	struct http_connection connection;
	for (unsigned int i = 0; i <= MAX_COMP_LEVEL; i++) {
		connection.compression_level = i;
		websocket_init(&ws, &connection, true, ws_on_error, NULL);
		param_val_comp_level[i][0] = ws.extension_compression.client_max_window_bits;
		param_val_comp_level[i][1] = ws.extension_compression.client_no_context_takeover;
		param_val_comp_level[i][2] = ws.extension_compression.server_max_window_bits;
		param_val_comp_level[i][3] = ws.extension_compression.server_no_context_takeover;
	}
}

/*
 * returns the minimum value of the window size, depending on the compression level,
 * and the window size in the http offer. This is the expected window size in the http response.
 * If you would like to check also the no_context_takeover, you first have to extend the max_window_val array
 * with this information.
 */
static unsigned int get_min(const char *param, unsigned int comp_level, unsigned int case_no)
{
	int param_no = -1;
	int cs = -1;
	if (strcmp(param, "client_max_window_bits") == 0) {
		param_no = 0;
		cs = 0;
	}
//	if (strcmp(param, "client_no_context_takeover") == 0) {
//		cs = 0;
//		param_no = 1;
//	}
	if (strcmp(param, "server_max_window_bits") == 0) {
		param_no = 2;
		cs = 1;
	}
//	if (strcmp(param, "server_no_context_takeover") == 0) {
//		param_no = 3;
//		cs = 1;
//	}
	if (cs == -1) return 99;
	unsigned int a = param_val_comp_level[comp_level][param_no];
	unsigned int b = max_window_val_c_s[case_no][cs];
	return a < b ? a : b;
}

struct F {
	F ()
	{
		text_correct = false;
		frame_correct = false;
		binary_correct = false;
		binary_frame_correct = false;
		got_error = false;
		fragmentation_buffer = (uint8_t *)malloc(text_length + 1);
		fragmentation_buffer_ptr = fragmentation_buffer;

		connection = alloc_http_connection();
		connection->br.writev = writev;
		connection->br.read_exactly = read_exactly;
		connection->br.close = close;
		connection->compression_level = 2;
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
	}

	~F()
	{
		if (!got_error) {
			free_connection(ws.connection);
		}
		free(fragmentation_buffer);
	}

	struct websocket ws;
	struct http_connection *connection;

	void setup_comp()
	{
		alloc_compression(&ws);
		ws.extension_compression.accepted = true;
		char response[] = "unset";
		ws.extension_compression.response = (char *)::malloc(sizeof(response));
	}

	void tear_down_comp()
	{
		free(ws.extension_compression.response);
		ws.extension_compression.response = NULL;
		free_compression(&ws);
		ws.extension_compression.accepted = false;
	}
};

BOOST_FIXTURE_TEST_CASE(test_comp_and_decomp_msg_simple, F)
{
	for (unsigned int i = 0; i <= MAX_COMP_LEVEL; i++) {
		ws.extension_compression.compression_level = i;
		setup_comp();
		int have;
		uint8_t src[text_length];
		::memcpy(src,text, text_length);
		uint8_t dest[text_length*2];

		have = websocket_compress(&ws, dest, src, text_length);
		char dest_txt[have];
		::memcpy(dest_txt,dest,have);
		text_received_comp(true, &ws, dest_txt, have, message_received);
		BOOST_CHECK_MESSAGE(text_correct == true, "Received message differs from orginal!");
		tear_down_comp();
		text_correct = false;
	}
}

BOOST_FIXTURE_TEST_CASE(test_comp_and_decomp_msg_5_times, F)
{
	for (unsigned int j = 0; j <= MAX_COMP_LEVEL; j++) {
		ws.extension_compression.compression_level = j;
		setup_comp();
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
		tear_down_comp();
	}
}

BOOST_FIXTURE_TEST_CASE(test_comp_and_decomp_msg_frag, F)
{
	for (unsigned int i = 0; i <= MAX_COMP_LEVEL; i++) {
		ws.extension_compression.compression_level = i;
		setup_comp();
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
		tear_down_comp();
		frame_correct = false;
	}
}

BOOST_FIXTURE_TEST_CASE(test_comp_and_decomp_binary_simple, F)
{
	for (unsigned int i = 0; i <= MAX_COMP_LEVEL; i++) {
		ws.extension_compression.compression_level = i;
		setup_comp();
		int have;
		uint8_t dest[text_length*2];
		have = websocket_compress(&ws, dest, binary, text_length);
		binary_received_comp(true, &ws, dest, have, binary_received);
		BOOST_CHECK_MESSAGE(binary_correct == true, "Received binary differs from orginal!");
		tear_down_comp();
		binary_correct = false;
	}
}

BOOST_FIXTURE_TEST_CASE(test_comp_and_decomp_binary_5_times, F)
{
	for (unsigned int j = 0; j <= MAX_COMP_LEVEL; j++) {
		ws.extension_compression.compression_level = j;
		setup_comp();
		int have;
		uint8_t dest[text_length*2];

		for(unsigned int i = 0; i < 5; i++) {
			have = websocket_compress(&ws, dest, binary, text_length);
			binary_received_comp(true, &ws, dest, have, binary_received);
			BOOST_CHECK_MESSAGE(binary_correct == true, "Received binary differs from orginal!");
			binary_correct = false;
		}
		tear_down_comp();
	}
}

BOOST_FIXTURE_TEST_CASE(test_comp_and_decomp_binary_frag, F)
{
	for (unsigned int i = 0; i <= MAX_COMP_LEVEL; i++) {
		ws.extension_compression.compression_level = i;
		setup_comp();
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
		tear_down_comp();
		binary_frame_correct = false;
	}
}

BOOST_FIXTURE_TEST_CASE(test_compression_and_decompression_binary_all_parameters,F)
{
	int have;
	uint8_t dest[text_length*2];

	for (unsigned int server_bits = 8; server_bits < 16; server_bits++) {
		ws.extension_compression.server_max_window_bits = server_bits;
		for (unsigned int client_bits = 8; client_bits < 16; client_bits++) {
			ws.extension_compression.client_max_window_bits = client_bits;
			for (unsigned int server_takeover = 0; server_takeover < 2; server_takeover++) {
				ws.extension_compression.server_no_context_takeover = server_takeover;
				for (unsigned int client_takeover = 0; client_takeover < 2; client_takeover++) {
					ws.extension_compression.client_no_context_takeover = client_takeover;
					setup_comp();
					for(unsigned int i = 0; i < 5; i++) {
						have = websocket_compress(&ws, dest, binary, text_length);
						binary_received_comp(true, &ws, dest, have, binary_received);
						BOOST_CHECK_MESSAGE(binary_correct == true, "Received message differs from orginal!");
						binary_correct = false;
					}
					tear_down_comp();
				}
			}
		}
	}
}

BOOST_FIXTURE_TEST_CASE(test_data_frame_rsv_unset, F)
{
	setup_comp();
	ws.binary_message_received = binary_received;
	ws.binary_frame_received = binary_frame_received;
	uint8_t mask[4] = {0xaa, 0x55, 0xcc, 0x11};

	read_buffer_length = 2 + sizeof(mask) + text_length;
	uint8_t readbuffer_uncomp[read_buffer_length];
	readbuffer_uncomp[1] = 0x80 | ((uint8_t) text_length);
	::memcpy(readbuffer_uncomp + 2, mask, 4);
	::memcpy(readbuffer_uncomp + 6, binary, text_length);
	mask_payload(readbuffer_uncomp + 6, text_length, mask);

	read_buffer_start = readbuffer_uncomp;
	read_buffer_ptr = readbuffer_uncomp + 1;

	readbuffer_uncomp[0] = FIN | TYPE_BINARY;
	ws_get_header(&ws, read_buffer_start, read_buffer_length);
	BOOST_CHECK_MESSAGE(binary_correct, "Received uncomp. message should be ok!");
	binary_correct = false;

	unsigned int half = text_length / 2;
	read_buffer_length = 2 + sizeof(mask) + half;
	readbuffer_uncomp[1] = 0x80 | ((uint8_t) half);
	::memcpy(readbuffer_uncomp + 2, mask, 4);
	::memcpy(readbuffer_uncomp + 6, binary, half);
	mask_payload(readbuffer_uncomp + 6, half, mask);

	read_buffer_start = readbuffer_uncomp;
	read_buffer_ptr = readbuffer_uncomp + 1;
	readbuffer_uncomp[0] = TYPE_BINARY;
	ws_get_header(&ws, read_buffer_start, read_buffer_length);

	read_buffer_length = 2 + sizeof(mask) + text_length - half;
	readbuffer_uncomp[1] = 0x80 | ((uint8_t) text_length - half);
	::memcpy(readbuffer_uncomp + 2, mask, 4);
	::memcpy(readbuffer_uncomp + 6, binary + half, text_length - half);
	mask_payload(readbuffer_uncomp + 6, text_length - half, mask);

	read_buffer_start = readbuffer_uncomp;
	read_buffer_ptr = readbuffer_uncomp + 1;
	readbuffer_uncomp[0] = FIN | TYPE_CONTINUATION;
	ws_get_header(&ws, read_buffer_start, read_buffer_length);
	BOOST_CHECK_MESSAGE(binary_frame_correct, "Received uncomp. frag. message should be ok!");
	binary_frame_correct = false;
	tear_down_comp();
}

BOOST_FIXTURE_TEST_CASE(test_data_frame_rsv_set, F)
{
	setup_comp();
	ws.binary_message_received = binary_received;
	ws.binary_frame_received = binary_frame_received;
	uint8_t mask[4] = {0xaa, 0x55, 0xcc, 0x11};
	uint8_t dest[text_length*2];
	int have = websocket_compress(&ws, dest, binary, text_length);
	unsigned int half = have / 2;
	mask_payload(dest, half, mask);
	mask_payload(dest + half, have - half, mask);

	read_buffer_length = 2 + sizeof(mask) + have;
	uint8_t readbuffer_comp[read_buffer_length];
	read_buffer_length = 2 + sizeof(mask) + half;
	readbuffer_comp[1] = 0x80 | ((uint8_t) half);
	::memcpy(readbuffer_comp + 2, mask, 4);
	::memcpy(readbuffer_comp + 6, dest, half);

	read_buffer_start = readbuffer_comp;
	read_buffer_ptr = readbuffer_comp +1;
	readbuffer_comp[0] = RSV1 | TYPE_BINARY;
	ws_get_header(&ws, read_buffer_start, read_buffer_length);
	BOOST_CHECK_MESSAGE(ws.ws_flags.is_frag_compressed == 1, "Compressed flag not set");

	read_buffer_length = 2 + sizeof(mask) + have - half;
	readbuffer_comp[1] = 0x80 | ((uint8_t) have - half);
	::memcpy(readbuffer_comp + 2, mask, 4);
	::memcpy(readbuffer_comp + 6, dest + half, have - half);

	read_buffer_start = readbuffer_comp;
	read_buffer_ptr = readbuffer_comp +1;
	readbuffer_comp[0] = FIN | RSV1 | TYPE_CONTINUATION;
	ws_get_header(&ws, read_buffer_start, read_buffer_length);
	BOOST_CHECK_MESSAGE(binary_frame_correct, "Received comp. frag. message should be ok!");
	BOOST_CHECK_MESSAGE(ws.ws_flags.is_frag_compressed == 0, "Compressed flag not unset");
	binary_frame_correct = false;

	have = websocket_compress(&ws, dest, binary, text_length);
	mask_payload(dest, have, mask);

	read_buffer_length = 2 + sizeof(mask) + have;
	readbuffer_comp[1] = 0x80 | ((uint8_t) have);
	::memcpy(readbuffer_comp + 2, mask, 4);
	::memcpy(readbuffer_comp + 6, dest, have);

	read_buffer_start = readbuffer_comp;
	read_buffer_ptr = readbuffer_comp +1;

	readbuffer_comp[0] = FIN | RSV1 | TYPE_BINARY;
	ws_get_header(&ws, read_buffer_start, read_buffer_length);
	BOOST_CHECK_MESSAGE(binary_correct, "Received comp. message should be ok!");
	BOOST_CHECK_MESSAGE(ws.ws_flags.is_frag_compressed == 0, "Compressed flag not unset");
	binary_correct = false;

	mask_payload(dest, have, mask);
	tear_down_comp();

	read_buffer_start = readbuffer_comp;
	read_buffer_ptr = readbuffer_comp + 1;

	readbuffer_comp[0] = FIN | RSV1 | TYPE_BINARY;
	ws_get_header(&ws, read_buffer_ptr, read_buffer_length);
	BOOST_CHECK_MESSAGE(got_error, "Error not called. RSV bit without compression is not allowed!");
}

BOOST_FIXTURE_TEST_CASE(test_rsv_bit_control_frame, F)
{
	setup_comp();
	ws.ping_received = binary_received;

	uint8_t mask[4] = {0xaa, 0x55, 0xcc, 0x11};
	read_buffer_length = 2 + sizeof(mask) + text_length;
	uint8_t readbuffer[read_buffer_length];
	readbuffer[1] = 0x80 | ((uint8_t) text_length);
	::memcpy(readbuffer + 2, mask, 4);
	::memcpy(readbuffer + 6, binary, text_length);
	mask_payload(readbuffer + 6, text_length, mask);

	read_buffer_start = readbuffer;
	read_buffer_ptr = readbuffer +1;

	readbuffer[0] = FIN | TYPE_PING;
	ws_get_header(&ws, read_buffer_start, read_buffer_length);
	BOOST_CHECK_MESSAGE(binary_correct, "received message should be ok!");
	binary_correct = false;

	read_buffer_start = readbuffer;
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
	const char pmd[] = "permessage-deflate";
	const char cmw[] = "client_max_window_bits";
	const char cnc[] = "client_no_context_takeover";
	const char smw[] = "server_max_window_bits";
	const char snc[] = "server_no_context_takeover";

	fill_param_values();
	const unsigned int cases = 4;
	max_window_val_c_s[0][0] = 0;	//client, if not present = 0
	max_window_val_c_s[0][1] = 15;	//server, default = 15
	max_window_val_c_s[1][0] = 10;
	max_window_val_c_s[1][1] = 10;
	max_window_val_c_s[2][0] = 15;
	max_window_val_c_s[2][1] = 15;
	max_window_val_c_s[3][0] = 0;
	max_window_val_c_s[3][1] = 9;
	char extension_line[cases][150] = {};
	sprintf(extension_line[0],"%s", pmd);
	sprintf(extension_line[1],"%s; %s=%d; %s; %s; %s=%d", pmd, cmw, max_window_val_c_s[1][0], cnc, snc, smw, max_window_val_c_s[1][1]);
	sprintf(extension_line[2],"%s; %s", pmd, cmw);
	sprintf(extension_line[3],"%s; %s=8, %s; %s=%d", pmd, smw, pmd, smw, max_window_val_c_s[3][1]);

	char expected[MAX_COMP_LEVEL + 1][cases][150] = {};
	sprintf(expected[1][0], "%s; %s=%d; %s; %s", pmd, smw, get_min(smw, 1, 0), cnc, snc);
	sprintf(expected[1][1], "%s; %s=%d; %s; %s; %s=%d", pmd, cmw, get_min(cmw, 1, 1), cnc, snc, smw,  get_min(smw, 1, 1));
	sprintf(expected[1][2], "%s; %s=%d; %s=%d; %s; %s", pmd, cmw,  get_min(cmw, 1, 2), smw, get_min(smw, 1, 2), cnc, snc);
	sprintf(expected[1][3], "%s; %s=%d; %s; %s", pmd, smw, get_min(smw, 1, 3), cnc, snc);

	sprintf(expected[2][0], "%s; %s=%d", pmd, smw, get_min(smw, 2, 0));
	sprintf(expected[2][1], "%s; %s=%d; %s; %s; %s=%d", pmd, cmw, get_min(cmw, 2, 1), cnc, snc, smw, get_min(smw, 2, 1));
	sprintf(expected[2][2], "%s; %s=%d; %s=%d", pmd, cmw, get_min(cmw, 2, 2), smw, get_min(smw, 2, 2));
	sprintf(expected[2][3], "%s; %s=%d", pmd, smw, get_min(smw, 2, 3));

	sprintf(expected[3][0], "%s", pmd);
	sprintf(expected[3][1], "%s; %s=%d; %s; %s; %s=%d", pmd, cmw, get_min(cmw, 3, 1), cnc, snc, smw, get_min(smw, 3, 1));
	sprintf(expected[3][2], "%s; %s=%d", pmd, cmw, get_min(cmw, 3, 2));
	sprintf(expected[3][3], "%s; %s=%d", pmd, smw, get_min(smw, 3, 3));

	for (unsigned int j = 0; j <= MAX_COMP_LEVEL; j++) {
		connection->compression_level = j;
		for (unsigned int i = 0; i < cases; i++) {
			websocket_init(&ws, connection, true, ws_on_error, NULL);
			ws.current_header_field = HEADER_SEC_WEBSOCKET_EXTENSIONS;
			websocket_upgrade_on_header_value(&parser, extension_line[i], strlen(extension_line[i]));
			if (ws.extension_compression.compression_level == 0) {
				BOOST_CHECK_MESSAGE(ws.extension_compression.response == NULL, "Response should be NULL");
				BOOST_CHECK_MESSAGE(!ws.extension_compression.accepted, "Extension should not be accepted!");
			} else {
				int ret = strcmp(ws.extension_compression.response, expected[j][i]);
				char str1[500];
				sprintf(str1, "Expected[%d][%d] \"%s\",\ngot \"%s\".\nIf you changed the comp level params or the way the response is generated,"
							  "your program may be correct and you've to adapt the case outcome.\n", j, i, expected[j][i], ws.extension_compression.response);
				BOOST_CHECK_MESSAGE(ret == 0, str1);
				char str2[50];
				sprintf(str2, "Extension %d should be accpeted!", i);
				BOOST_CHECK_MESSAGE(ws.extension_compression.accepted, str2);
				BOOST_CHECK_MESSAGE(max_window_val_c_s[i][0] == 0 ? (ws.extension_compression.client_max_window_bits == 15)
				                                                  : (ws.extension_compression.client_max_window_bits == get_min(cmw, j, i)),
				                                                  "client_max_window_bits not adapted!");
				BOOST_CHECK_MESSAGE(ws.extension_compression.server_max_window_bits == get_min(smw, j, i), "server_max_window_bits not adapted!");
			}
			if (ws.extension_compression.accepted) tear_down_comp();
		}
	}
}

BOOST_FIXTURE_TEST_CASE(test_parse_html_extension_field_illegal, F)
{
	http_parser parser;
	parser.data = &ws;
	ws.connection->parser = parser;
	const unsigned int cases = 4;
	const char extension_line[cases][150]={{"permessage-deflate; server_max_window_bits=7"},
	                                       {"permessage-deflate; client_no_context_takeover; client_no_context_takeover"},
	                                       {"permessage-deflate; xxxxxxxxxxxxxxxxxxxxxxxxxx, client_no_context_takeover"},
	                                       {"permeeeege-deeeeee; server_max_window_bits=10"}};

	for (unsigned int j = 0; j <= MAX_COMP_LEVEL; j++) {
		connection->compression_level = j;
		for (unsigned int i = 0; i < cases; i++) {
			websocket_init(&ws, connection, true, ws_on_error, NULL);
			ws.current_header_field = HEADER_SEC_WEBSOCKET_EXTENSIONS;
			websocket_upgrade_on_header_value(&parser, extension_line[i], strlen(extension_line[i]));
			char str[50];
			sprintf(str, "Extension %d should not be accpeted!", i);
			BOOST_CHECK_MESSAGE(!ws.extension_compression.accepted, str);
			if (ws.extension_compression.accepted) tear_down_comp();
			if (ws.extension_compression.response != NULL) free(ws.extension_compression.response);
		}
	}
}
