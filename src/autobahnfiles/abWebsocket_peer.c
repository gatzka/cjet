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
#include "peer.h"
#include "sha1/sha1.h"
#include "websocket.h"
#include "websocket_peer.h"
#include "utf8_checker.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

static struct ab_ws_peer {
	uint8_t *binary_frame_buffer;
	size_t binary_frame_buffer_size;
	char *text_frame_buffer;
	size_t text_frame_buffer_size;
	struct cjet_utf8_checker checker;
} ab_peer;

static int ws_send_message(const struct peer *p, char *rendered, size_t len)
{
	const struct websocket_peer *ws_peer = const_container_of(p, struct websocket_peer, peer);
	return websocket_send_text_frame(&ws_peer->websocket, rendered, len);
}

static int ws_send_binary(const struct peer *p, uint8_t *payload, size_t len)
{
	const struct websocket_peer *ws_peer = const_container_of(p, struct websocket_peer, peer);
	return websocket_send_binary_frame(&ws_peer->websocket, payload, len);
}

static void free_websocket_peer(struct websocket_peer *ws_peer)
{
	if (ab_peer.text_frame_buffer != NULL) {
		free(ab_peer.text_frame_buffer);
		ab_peer.text_frame_buffer = NULL;
		ab_peer.text_frame_buffer_size = 0;
	}
	if (ab_peer.binary_frame_buffer != NULL) {
		free(ab_peer.text_frame_buffer);
		ab_peer.binary_frame_buffer = NULL;
		ab_peer.binary_frame_buffer_size = 0;
	}
	free_peer_resources(&ws_peer->peer);
	cjet_free(ws_peer);
}

static void free_websocket_peer_callback(struct websocket *s)
{
	struct websocket_peer *ws_peer = container_of(s, struct websocket_peer, websocket);
	free_websocket_peer(ws_peer);
}

static void free_websocket_peer_on_error(void *context)
{
	struct websocket_peer *ws_peer = (struct websocket_peer *)context;
	websocket_close(&ws_peer->websocket, WS_CLOSE_GOING_AWAY);
	free_websocket_peer(ws_peer);
}

static enum websocket_callback_return text_message_callback(struct websocket *s, char *msg, size_t length)
{
	struct websocket_peer *ws_peer = container_of(s, struct websocket_peer, websocket);
	log_info("recieved message and send back: %.*s",length,msg);
	if (!cjet_is_text_valid(&(ab_peer.checker), msg, length, true)) {
		return WS_CLOSED;
	}
	int ret = ws_send_message(&ws_peer->peer, msg, length);
	if (unlikely(ret < 0)) {
		return WS_ERROR;
	} else {
		return WS_OK;
	}
}

static enum websocket_callback_return text_frame_callback(struct websocket *s, char *msg, size_t length, bool is_last_frame)
{
	struct websocket_peer *ws_peer = container_of(s, struct websocket_peer, websocket);
	enum websocket_callback_return ret = WS_OK;
	if (!cjet_is_text_valid(&(ab_peer.checker), msg, length, is_last_frame)) {
		return WS_CLOSED;
	}
	if (length != 0) {
		ab_peer.text_frame_buffer = realloc(ab_peer.text_frame_buffer, ab_peer.text_frame_buffer_size + length);
		if (unlikely(ab_peer.text_frame_buffer == NULL)) {
			log_err("Not enough memory for fragmented message!");
			return WS_ERROR;
		}
		memcpy(ab_peer.text_frame_buffer + ab_peer.text_frame_buffer_size, msg, length);
		ab_peer.text_frame_buffer_size += length;
	}
	if (is_last_frame) {
		ret = text_message_callback(&ws_peer->websocket, ab_peer.text_frame_buffer, ab_peer.text_frame_buffer_size);
		if (ab_peer.text_frame_buffer != NULL) {
			free(ab_peer.text_frame_buffer);
			ab_peer.text_frame_buffer = NULL;
			ab_peer.text_frame_buffer_size = 0;
		}
	}
	return ret;
}

static enum websocket_callback_return binary_message_callback(struct websocket *s, uint8_t *msg, size_t length)
{
	struct websocket_peer *ws_peer = container_of(s, struct websocket_peer, websocket);
	log_info("recieved binary and send back: %.*s",length,msg);
	int ret = ws_send_binary(&ws_peer->peer, msg, length);
	if (unlikely(ret < 0)) {
		return WS_ERROR;
	} else {
		return WS_OK;
	}
}

static enum websocket_callback_return binary_frame_callback(struct websocket *s, uint8_t *msg, size_t length, bool is_last_frame)
{
	struct websocket_peer *ws_peer = container_of(s, struct websocket_peer, websocket);
	enum websocket_callback_return ret = WS_OK;
	if (length != 0) {
		ab_peer.binary_frame_buffer = realloc(ab_peer.binary_frame_buffer, ab_peer.binary_frame_buffer_size + length);
		if (unlikely(ab_peer.binary_frame_buffer == NULL)) {
			log_err("Not enough memory for fragmented message!");
			return WS_ERROR;
		}
		memcpy(ab_peer.binary_frame_buffer + ab_peer.binary_frame_buffer_size, msg, length);
		ab_peer.binary_frame_buffer_size += length;
	}
	if (is_last_frame) {
		ret = binary_message_callback(&ws_peer->websocket, ab_peer.binary_frame_buffer, ab_peer.binary_frame_buffer_size);
		if (ab_peer.binary_frame_buffer != NULL) {
			free(ab_peer.binary_frame_buffer);
			ab_peer.binary_frame_buffer = NULL;
			ab_peer.binary_frame_buffer_size = 0;
		}
	}
	return ret;
}

static enum websocket_callback_return close_callback(struct websocket *s, enum ws_status_code status_code)
{
	struct websocket_peer *ws_peer = container_of(s, struct websocket_peer, websocket);
	log_peer_info(&ws_peer->peer, "Websocket peer closed connection: %d\n", status_code);
	free_websocket_peer(ws_peer);
	return WS_CLOSED;
}

static enum websocket_callback_return pong_received(struct websocket *s, uint8_t *msg, size_t length)
{
	char buffer[50];
	size_t len = MIN(sizeof(buffer), length);
	memcpy(buffer, msg, len);
	if (len < sizeof(buffer)) {
		buffer[len] = '\0';
	} else {
		buffer[sizeof(buffer) - 1] = '\0';
	}
	struct websocket_peer *ws_peer = container_of(s, struct websocket_peer, websocket);
	log_peer_info(&ws_peer->peer, "PONG received: %s\n", buffer);
	return WS_OK;
}

static void peer_close_websocket_peer(struct peer *p)
{
	struct websocket_peer *ws_peer = container_of(p, struct websocket_peer, peer);
	websocket_close(&ws_peer->websocket, WS_CLOSE_GOING_AWAY);
	free_websocket_peer(ws_peer);
}

static void init_ab_websocket_peer()
{
	ab_peer.binary_frame_buffer = NULL;
	ab_peer.binary_frame_buffer_size = 0;
	ab_peer.text_frame_buffer = NULL;
	ab_peer.text_frame_buffer_size = 0;
	cjet_init_checker(&(ab_peer.checker));
}

static int init_websocket_peer(struct websocket_peer *ws_peer, struct http_connection *connection, bool is_local_connection)
{
	static const char *sub_protocol = NULL;
	init_ab_websocket_peer();

	init_peer(&ws_peer->peer, is_local_connection, connection->server->ev.loop);
	ws_peer->peer.send_message = ws_send_message;
	ws_peer->peer.close = peer_close_websocket_peer;

	struct buffered_reader *br = &connection->br;
	br->set_error_handler(br->this_ptr, free_websocket_peer_on_error, ws_peer);

	int ret = websocket_init(&ws_peer->websocket, connection, true, free_websocket_peer_callback, sub_protocol);
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

int alloc_websocket_peer(struct http_connection *connection)
{
	struct websocket_peer *ws_peer = cjet_calloc(1, sizeof(*ws_peer));
	if (ws_peer == NULL) {
		return -1;
	}

	connection->parser.data = &ws_peer->websocket;
	return init_websocket_peer(ws_peer, connection, connection->is_local_connection);
}
