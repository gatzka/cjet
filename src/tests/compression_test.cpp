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

static bool text_correct = false;
static bool frame_correct = false;
static bool binary_correct = false;
static bool binary_frame_correct = false;
char text[] = "Hello World! Hello World!";
size_t text_length = 26;
uint8_t binary[] = {0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21, 0x20,
                    0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21, 0x0};

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

struct F {
	F ()
	{
		ws.extension_compression.name = "permessage-deflate";
		ws.extension_compression.client_no_context_takeover = false;
		ws.extension_compression.client_max_window_bits = 15;
		ws.extension_compression.response = NULL;
		ws.extension_compression.accepted = false;
		ws.extension_compression.dummy_ptr = &ws.extension_compression.strm_private_comp;
		ws.extension_compression.strm_comp = &ws.extension_compression.dummy_ptr;
		alloc_compression(&ws);
	}

	~F()
	{
		if (ws.extension_compression.response != NULL) {
			free(ws.extension_compression.response);
		}
		free_compression(&ws);
		text_correct = false;
		frame_correct = false;
		binary_correct = false;
		binary_frame_correct = false;
	}

	struct websocket ws;
	struct http_connection *connection;
};

BOOST_FIXTURE_TEST_CASE(comp_and_decomp_msg_simple, F)
{
	int have;
	uint8_t src [text_length];
	memcpy(src,text, text_length);
	uint8_t dest[text_length*2];

	have = websocket_compress(&ws, dest, src, text_length);
	char dest_txt[have];
	memcpy(dest_txt,dest,have);
	message_received_comp(true, &ws, dest_txt, have, message_received);
	BOOST_CHECK_MESSAGE(text_correct == true, "Received message differs from orginal!");
}

BOOST_FIXTURE_TEST_CASE(comp_and_decomp_msg_5_times, F)
{
	int have;
	uint8_t src [text_length];
	memcpy(src,text, text_length);
	uint8_t dest[text_length*2];

	for(unsigned int i = 0; i < 5; i++) {
		have = websocket_compress(&ws, dest, src, text_length);
		char dest_txt[have];
		memcpy(dest_txt,dest,have);
		message_received_comp(true, &ws, dest_txt, have, message_received);
		BOOST_CHECK_MESSAGE(text_correct == true, "Received message differs from orginal!");
		text_correct = false;
	}
}

BOOST_FIXTURE_TEST_CASE(comp_and_decomp_msg_frag, F)
{
	int have;
	websocket_callback_return ret;
	uint8_t src [text_length];
	memcpy(src, text, text_length);
	uint8_t dest[text_length*2];

	have = websocket_compress(&ws, dest, src, text_length);
	char dest_txt[have];
	memcpy(dest_txt, dest, have);
	size_t cut = have / 2;

	ret = frame_received_comp(true, &ws, dest_txt, cut, false, frame_received);
	BOOST_CHECK_MESSAGE(ret == WS_OK, "Problem with first fragment");

	ret = frame_received_comp(true, &ws, dest_txt + cut, have - cut, true, frame_received);
	BOOST_CHECK_MESSAGE(ret == WS_OK, "Error during decomp last fragment!");
	BOOST_CHECK_MESSAGE(frame_correct == true, "Received fragments differ from orginal!");
}

BOOST_FIXTURE_TEST_CASE(comp_and_decomp_binary_simple, F)
{
	int have;
	uint8_t dest[text_length*2];
	have = websocket_compress(&ws, dest, binary, text_length);
	binary_received_comp(true, &ws, dest, have, binary_received);
	BOOST_CHECK_MESSAGE(binary_correct == true, "Received binary differs from orginal!");
}

BOOST_FIXTURE_TEST_CASE(comp_and_decomp_binary_5_times, F)
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

BOOST_FIXTURE_TEST_CASE(comp_and_decomp_binary_frag, F)
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

//TODO Tests for opening handshanke and header control (rsv-bits etc.)
