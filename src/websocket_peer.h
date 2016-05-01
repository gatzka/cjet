/*
 *The MIT License (MIT)
 *
 * Copyright (c) <2014> <Stephan Gatzka>
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

#ifndef CJET_WEBSOCKET_PEER_H
#define CJET_WEBSOCKET_PEER_H

#include <stdint.h>

#include "socket_peer.h"

enum header_field {
	HEADER_UNKNOWN,
	HEADER_SEC_WEBSOCKET_KEY,
	HEADER_SEC_WEBSOCKET_VERSION,
	HEADER_SEC_WEBSOCKET_PROTOCOL,
	HEADER_UPGRADE,
	HEADER_CONNECTION_UPGRADE,
};

#define SEC_WEB_SOCKET_KEY_LENGTH 24
#define SEC_WEB_SOCKET_GUID_LENGTH 36

enum ws_protocol_state {
	WS_READING_HEADER,
	WS_READING_FIRST_LENGTH,
	WS_READING_LENGTH16,
	WS_READING_LENGTH64,
	WS_READING_MASK,
	WS_READING_PAYLOAD
};

#define WS_CONTINUATION_FRAME 0x0
#define WS_TEXT_FRAME 0x1
#define WS_BINARY_FRAME 0x2
#define WS_CLOSE_FRAME 0x8
#define WS_PING_FRAME 0x9
#define WS_PONG_FRAME 0x0a

struct ws_peer {
	struct socket_peer s_peer;
	http_parser parser;
	http_parser_settings parser_settings;
	enum header_field current_header_field;
	uint8_t sec_web_socket_key[SEC_WEB_SOCKET_KEY_LENGTH + SEC_WEB_SOCKET_GUID_LENGTH];
	struct {
		unsigned int header_upgrade: 1;
		unsigned int connection_upgrade: 1;
	} flags;
	enum ws_protocol_state ws_protocol;
	uint64_t length;
	uint8_t mask[4];
	struct {
		unsigned int fin: 1;
		unsigned int opcode: 4;
		unsigned int mask: 1;
	} ws_flags;
};

struct ws_peer *alloc_wsjet_peer(const struct eventloop *loop, int fd);
void free_wsjet_peer(const struct eventloop *loop, struct ws_peer *p);

int send_ws_upgrade_response(struct ws_peer *p, const char *begin, size_t begin_length, const char *key, size_t key_length, const char *end, size_t end_length);
int send_ws_response(struct ws_peer *p, const char *header, size_t header_size, const char *payload, size_t payload_size);


#endif
