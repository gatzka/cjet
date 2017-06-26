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

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include "alloc.h"
#include "base64.h"
#include "compiler.h"
#include "http_connection.h"
#include "jet_endian.h"
#include "jet_string.h"
#include "log.h"
#include "parse.h"
#include "sha1/sha1.h"
#include "websocket.h"
#include "abWebsocket_peer.h"
#include "utf8_checker.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

static void free_ab_ws_peer(struct ab_ws_peer *ws_peer)
{
	if (ws_peer->text_frame_buffer != NULL) {
		free(ws_peer->text_frame_buffer);
		ws_peer->text_frame_buffer = NULL;
		ws_peer->text_frame_buffer_size = 0;
		ws_peer->text_frame_buffer_ptr = 0;
	}
	if (ws_peer->binary_frame_buffer != NULL) {
		free(ws_peer->binary_frame_buffer);
		ws_peer->binary_frame_buffer = NULL;
		ws_peer->binary_frame_buffer_size = 0;
		ws_peer->binary_frame_buffer_ptr = 0;
	}
	cjet_free(ws_peer);
}

static void free_ab_ws_peer_callback(struct websocket *s)
{
	struct ab_ws_peer *ws_peer = container_of(s, struct ab_ws_peer, websocket);
	free_ab_ws_peer(ws_peer);
}

static void free_ab_ws_peer_on_error(void *context)
{
	struct ab_ws_peer *ws_peer = (struct ab_ws_peer *)context;
	websocket_close(&ws_peer->websocket, WS_CLOSE_GOING_AWAY);
	free_ab_ws_peer(ws_peer);
}

static enum websocket_callback_return text_message_callback(struct websocket *s, char *msg, size_t length)
{
	struct ab_ws_peer *ws_peer = container_of(s, struct ab_ws_peer, websocket);
	if (!cjet_is_word_sequence_valid_auto_alligned(&(ws_peer->checker), msg, length, true)) {
		return WS_CLOSED;
	}
	int ret = websocket_send_text_frame(s, msg, length);
	size_t writelength = length;
	if (writelength > 200) {
		writelength = 200;
		*(msg + 199) = '\0';
	}
	log_info("recieved message and send back: %.*s", writelength, msg);
	if (unlikely(ret < 0)) {
		return WS_ERROR;
	} else {
		return WS_OK;
	}
}

static enum websocket_callback_return text_frame_callback(struct websocket *s, char *msg, size_t length, bool is_last_frame)
{
	struct ab_ws_peer *ws_peer = container_of(s, struct ab_ws_peer, websocket);
	enum websocket_callback_return ret = WS_OK;
	if (!cjet_is_word_sequence_valid_auto_alligned(&(ws_peer->checker), msg, length, is_last_frame)) {
		return WS_CLOSED;
	}
	if (length != 0) {
		if (ws_peer->text_frame_buffer == NULL) {
			ws_peer->text_frame_buffer = malloc(length * 3);
			if (unlikely(ws_peer->text_frame_buffer == NULL)) {
				log_err("Not enough memory for fragmented message!");
				ws_peer->text_frame_buffer_ptr = 0;
				ws_peer->text_frame_buffer_size = 0;
				return WS_ERROR;
			}
			ws_peer->text_frame_buffer_size = length * 3;
			ws_peer->text_frame_buffer_ptr = 0;
		}
		if (length > (ws_peer->text_frame_buffer_size - ws_peer->text_frame_buffer_ptr)) {
			ws_peer->text_frame_buffer = realloc(ws_peer->text_frame_buffer, ws_peer->text_frame_buffer_size * 2);
			if (unlikely(ws_peer->text_frame_buffer == NULL)) {
				log_err("Not enough memory for fragmented message!");
				ws_peer->text_frame_buffer_ptr = 0;
				ws_peer->text_frame_buffer_size = 0;
				return WS_ERROR;
			}
			ws_peer->text_frame_buffer_size *= 2;
		}
		memcpy(ws_peer->text_frame_buffer + ws_peer->text_frame_buffer_ptr, msg, length);
		ws_peer->text_frame_buffer_ptr += length;
	}
	if (is_last_frame) {
		ret = text_message_callback(&ws_peer->websocket, ws_peer->text_frame_buffer, ws_peer->text_frame_buffer_ptr);
		ws_peer->text_frame_buffer_ptr = 0;
	}
	return ret;
}

static enum websocket_callback_return binary_message_callback(struct websocket *s, uint8_t *msg, size_t length)
{
	int ret = websocket_send_binary_frame(s, msg, length);
	size_t writelength = length;
	if (writelength > 200) {
		writelength = 200;
		*(msg + 199) = '\0';
	}
	log_info("recieved binary and send back: %.*s",writelength,msg);
	if (unlikely(ret < 0)) {
		return WS_ERROR;
	} else {
		return WS_OK;
	}
}

static enum websocket_callback_return binary_frame_callback(struct websocket *s, uint8_t *msg, size_t length, bool is_last_frame)
{
	struct ab_ws_peer *ws_peer = container_of(s, struct ab_ws_peer, websocket);
	enum websocket_callback_return ret = WS_OK;
	if (length != 0) {
		if (ws_peer->binary_frame_buffer == NULL) {
			ws_peer->binary_frame_buffer = malloc(length * 3);
			if (unlikely(ws_peer->binary_frame_buffer == NULL)) {
				log_err("Not enough memory for fragmented message!");
				ws_peer->binary_frame_buffer_ptr = 0;
				ws_peer->binary_frame_buffer_size = 0;
				return WS_ERROR;
			}
			ws_peer->binary_frame_buffer_size = length * 3;
			ws_peer->binary_frame_buffer_ptr = 0;
		}
		if (length > (ws_peer->binary_frame_buffer_size - ws_peer->binary_frame_buffer_ptr)) {
			ws_peer->binary_frame_buffer = realloc(ws_peer->binary_frame_buffer, ws_peer->binary_frame_buffer_size * 2);
			if (unlikely(ws_peer->binary_frame_buffer == NULL)) {
				log_err("Not enough memory for fragmented message!");
				ws_peer->binary_frame_buffer_ptr = 0;
				ws_peer->binary_frame_buffer_size = 0;
				return WS_ERROR;
			}
			ws_peer->binary_frame_buffer_size *= 2;
		}
		memcpy(ws_peer->binary_frame_buffer + ws_peer->binary_frame_buffer_ptr, msg, length);
		ws_peer->binary_frame_buffer_ptr += length;
	}
	if (is_last_frame) {
		ret = binary_message_callback(&ws_peer->websocket, ws_peer->binary_frame_buffer, ws_peer->binary_frame_buffer_ptr);
		ws_peer->binary_frame_buffer_ptr = 0;
	}
	return ret;
}

static enum websocket_callback_return close_callback(struct websocket *s, enum ws_status_code status_code)
{
	struct ab_ws_peer *ws_peer = container_of(s, struct ab_ws_peer, websocket);
	log_info("Websocket peer closed connection: %d\n", status_code);
	free_ab_ws_peer(ws_peer);
	return WS_CLOSED;
}

static enum websocket_callback_return pong_received(struct websocket *s, uint8_t *msg, size_t length)
{
	(void) *s;
	char buffer[50];
	size_t len = MIN(sizeof(buffer), length);
	memcpy(buffer, msg, len);
	if (len < sizeof(buffer)) {
		buffer[len] = '\0';
	} else {
		buffer[sizeof(buffer) - 1] = '\0';
	}
	log_info("PONG received: %s\n", buffer);
	return WS_OK;
}

static void init_ab_ab_ws_peer(struct ab_ws_peer *ws_peer)
{
	ws_peer->binary_frame_buffer = NULL;
	ws_peer->binary_frame_buffer_size = 0;
	ws_peer->binary_frame_buffer_ptr = 0;
	ws_peer->text_frame_buffer = NULL;
	ws_peer->text_frame_buffer_size = 0;
	ws_peer->text_frame_buffer_ptr = 0;
	cjet_init_checker(&(ws_peer->checker));
}

static int init_ab_ws_peer(struct ab_ws_peer *ws_peer, struct http_connection *connection)
{
	static const char *sub_protocol = NULL;
	init_ab_ab_ws_peer(ws_peer);

	struct buffered_reader *br = &connection->br;
	br->set_error_handler(br->this_ptr, free_ab_ws_peer_on_error, ws_peer);

	int ret = websocket_init(&ws_peer->websocket, connection, true, free_ab_ws_peer_callback, sub_protocol);
	if (ret < 0) {
		return -1;
	}
	ws_peer->websocket.text_message_received = text_message_callback;
	ws_peer->websocket.text_frame_received = text_frame_callback;
	ws_peer->websocket.binary_message_received = binary_message_callback;
	ws_peer->websocket.binary_frame_received = binary_frame_callback;
	ws_peer->websocket.close_received = close_callback;
	ws_peer->websocket.pong_received = pong_received;

	br->read_until(br->this_ptr, "\r\n", websocket_read_header_line, &ws_peer->websocket);
	return 0;
}

int alloc_abWebsocket_peer(struct http_connection *connection)
{
	struct ab_ws_peer *ws_peer = cjet_calloc(1, sizeof(*ws_peer));
	if (ws_peer == NULL) {
		return -1;
	}

	connection->parser.data = &ws_peer->websocket;
	return init_ab_ws_peer(ws_peer, connection);
}
