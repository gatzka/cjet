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

#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>
#include <unistd.h>

#include "base64.h"
#include "compiler.h"
#include "http_connection.h"
#include "jet_endian.h"
#include "jet_string.h"
#include "log.h"
#include "parse.h"
#include "peer.h"
#include "sha1/sha1.h"
#include "websocket_peer.h"
#include "websocket.h"

#ifndef ARRAY_SIZE
 #define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

#define CRLF "\r\n"

#define WS_CONTINUATION_FRAME 0x0
#define WS_TEXT_FRAME 0x1
#define WS_BINARY_FRAME 0x2
#define WS_CLOSE_FRAME 0x8
#define WS_PING_FRAME 0x9
#define WS_PONG_FRAME 0x0a

static int ws_send_message(struct peer *p, const char *rendered, size_t len)
{
	struct websocket_peer *ws_peer = container_of(p, struct websocket_peer, peer);
	return websocket_send_frame(&ws_peer->websocket, false, 0x00, rendered, len);
}

void free_websocket_peer(struct websocket_peer *p)
{
	free_peer_resources(&p->peer);
	websocket_free(&p->websocket);
	free(p);
}

static void free_websocket_peer_on_error(void *context)
{
	struct websocket_peer *ws_peer = (struct websocket_peer *)context;
	free_websocket_peer(ws_peer);
}

static void close_websocket_peer(struct peer *p)
{
	struct websocket_peer *ws_peer = container_of(p, struct websocket_peer, peer);
	free_websocket_peer(ws_peer);
}

static void init_websocket_peer(struct websocket_peer *ws_peer, struct http_connection *connection)
{
	init_peer(&ws_peer->peer);
	ws_peer->peer.send_message = ws_send_message;
	ws_peer->peer.close = close_websocket_peer;
	buffered_socket_set_error(connection->bs, free_websocket_peer_on_error, ws_peer);
	websocket_init(&ws_peer->websocket, connection);

	buffered_socket_read_until(connection->bs, CRLF, websocket_read_header_line, &ws_peer->websocket);
}

int alloc_websocket_peer(struct http_connection *connection)
{
	struct websocket_peer *ws_peer = calloc(1, sizeof(*ws_peer));
	if (ws_peer == NULL) {
		return -1;
	}

	connection->parser.data = &ws_peer->websocket;
	init_websocket_peer(ws_peer, connection);
	return 0;
}
