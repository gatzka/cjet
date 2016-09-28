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

#ifndef CJET_WEBSOCKET_H
#define CJET_WEBSOCKET_H

#include <stdbool.h>
#include <stdint.h>

#include "http_connection.h"
#include "http-parser/http_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SEC_WEB_SOCKET_KEY_LENGTH 24
#define SEC_WEB_SOCKET_GUID_LENGTH 36

enum header_field {
	HEADER_UNKNOWN,
	HEADER_SEC_WEBSOCKET_KEY,
	HEADER_SEC_WEBSOCKET_VERSION,
	HEADER_SEC_WEBSOCKET_PROTOCOL,
};

enum websocket_callback_return {
	WS_CLOSED,
	WS_ERROR,
	WS_OK
};

struct websocket {
	struct http_connection *connection;
	bool is_server;
	bool upgrade_complete;

	uint8_t sec_web_socket_key[SEC_WEB_SOCKET_KEY_LENGTH + SEC_WEB_SOCKET_GUID_LENGTH];
	enum header_field current_header_field;

	struct {
		unsigned int fin: 1;
		unsigned int opcode: 4;
		unsigned int mask: 1;
	} ws_flags;
	uint64_t length;
	uint8_t mask[4];
	void (*on_error)(struct websocket *s);
	enum websocket_callback_return (*text_message_received)(struct websocket *s, char *msg, size_t length);
	enum websocket_callback_return (*text_frame_received)(struct websocket *s, char *msg, size_t length, bool is_last_frame);
	enum websocket_callback_return (*binary_message_received)(struct websocket *s, uint8_t *msg, size_t length);
	enum websocket_callback_return (*binary_frame_received)(struct websocket *s, uint8_t *msg, size_t length, bool is_last_frame);
	enum websocket_callback_return (*ping_received)(struct websocket *s, uint8_t *msg, size_t length);
	enum websocket_callback_return (*pong_received)(struct websocket *s, uint8_t *msg, size_t length);
	enum websocket_callback_return (*close_received)(struct websocket *s, uint16_t status_code, char *msg, size_t length);
	bool protocol_requested;
	struct {
		const char *name;
		bool found;
	} sub_protocol;
};

int websocket_init_random(void);
void websocket_fill_mask_randomly(uint8_t mask[4]);

int websocket_init(struct websocket *ws, struct http_connection *connection, bool is_server, void (*on_error)(struct websocket *s), const char *sub_protocol);
void websocket_free(struct websocket *ws);
enum bs_read_callback_return websocket_read_header_line(void *context, uint8_t *buf, size_t len);
enum bs_read_callback_return ws_get_header(void *context, uint8_t *buf, size_t len);

int websocket_upgrade_on_header_field(http_parser *p, const char *at, size_t length);
int websocket_upgrade_on_headers_complete(http_parser *parser);
int websocket_upgrade_on_header_value(http_parser *p, const char *at, size_t length);
int websocket_send_text_frame(struct websocket *s, char *payload, size_t length);
int websocket_send_binary_frame(struct websocket *s, uint8_t *payload, size_t length);
int websocket_send_close_frame(struct websocket *s, uint16_t status_code, const char *payload, size_t length);
int websocket_send_ping_frame(struct websocket *s, uint8_t *payload, size_t length);
int websocket_send_pong_frame(struct websocket *s, uint8_t *payload, size_t length);

#ifdef __cplusplus
}
#endif

#endif
