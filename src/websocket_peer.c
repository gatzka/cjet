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

#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>

#include "compiler.h"
#include "http_server.h"
#include "jet_endian.h"
#include "parse.h"
#include "peer.h"
#include "websocket_peer.h"

#ifndef ARRAY_SIZE
# define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

static const uint8_t WS_MASK_SET = 0x80;
static const uint8_t WS_HEADER_FIN = 0x80;

#define WS_CONTINUATION_FRAME 0x0
#define WS_TEXT_FRAME 0x1
#define WS_BINARY_FRAME 0x2
#define WS_CLOSE_FRAME 0x8
#define WS_PING_FRAME 0x9
#define WS_PONG_FRAME 0x0a

static int ws_send_frame(struct websocket_peer *p, bool shall_mask, uint32_t mask, const char *payload, size_t length)
{
	char ws_header[14];
	uint8_t first_len;
	size_t header_index = 2;

	ws_header[0] = (uint8_t)(WS_TEXT_FRAME | WS_HEADER_FIN);
	if (length < 126) {
		first_len = (uint8_t)length;
	} else if (length < 65536) {
		uint16_t be_len = jet_htobe16((uint16_t)length);
		memcpy(&ws_header[2], &be_len, sizeof(be_len));
		header_index += sizeof(be_len);
		first_len = 126;
	} else {
		uint64_t be_len = jet_htobe64((uint64_t)length);
		memcpy(&ws_header[2], &be_len, sizeof(be_len));
		header_index += sizeof(be_len);
		first_len = 127;
	}

	if (shall_mask) {
		first_len |= WS_MASK_SET;
		memcpy(&ws_header[header_index], &mask, sizeof(mask));
		header_index += sizeof(mask);
	}
	ws_header[1] = first_len;

	struct buffered_socket_io_vector iov[2];
	iov[0].iov_base = ws_header;
	iov[0].iov_len = header_index;
	iov[1].iov_base = payload;
	iov[1].iov_len = length;
	return buffered_socket_writev(p->bs, iov, ARRAY_SIZE(iov));
}

static int ws_send_message(struct peer *p, const char *rendered, size_t len)
{
	struct websocket_peer *ws_peer = container_of(p, struct websocket_peer, peer);
	return ws_send_frame(ws_peer, false, 0x00, rendered, len);
}

static void free_websocket_peer(struct websocket_peer *p)
{
	free_peer(&p->peer);
	buffered_socket_close(p->bs);
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

static void unmask_payload(char *buffer, uint8_t *mask, unsigned int length)
{
	for (unsigned int i= 0; i < length; i++) {
		buffer[i] = buffer[i] ^ (mask[i % 4]);
	}
}

static int ws_handle_frame(struct websocket_peer *ws_peer, char *msg, unsigned int length)
{
	int ret;
	switch (ws_peer->ws_flags.opcode) {
	case WS_CONTINUATION_FRAME:
		log_peer_err(&ws_peer->peer, "Fragmented websocket frame not supported!\n");
		return -1;

	case WS_BINARY_FRAME:
	case WS_TEXT_FRAME:
		ret = parse_message(msg, length, &ws_peer->peer);
		if (unlikely(ret == -1)) {
			return -1;
		}
		break;

	case WS_PING_FRAME:

		break;

	case WS_PONG_FRAME:

		break;

	case WS_CLOSE_FRAME:

		break;

	default:
		log_peer_err(&ws_peer->peer, "Unsupported websocket frame!\n");
		return -1;
	}

	return 0;
}

static void ws_get_header(void *context, char *buf, ssize_t len);

static void ws_get_payload(void *context, char *buf, ssize_t len)
{
	struct websocket_peer *ws_peer = (struct websocket_peer *)context;

	if (likely(len > 0)) {
		if (ws_peer->ws_flags.mask == 1) {
			unmask_payload(buf, ws_peer->mask, len);
			int ret = ws_handle_frame(ws_peer, buf, len);
			if (likely(ret == 0)) {
				buffered_socket_read_exactly(ws_peer->bs, 1, ws_get_header, ws_peer);
			} else {
				free_websocket_peer(ws_peer);
			}
		}
	} else {
		if (len < 0) {
			log_peer_err(&ws_peer->peer, "Error while reading websocket payload!\n");
		}
		free_websocket_peer(ws_peer);
	}
}

static void ws_get_mask(void *context, char *buf, ssize_t len)
{
	struct websocket_peer *ws_peer = (struct websocket_peer *)context;

	if (likely(len > 0)) {
		memcpy(ws_peer->mask, buf, sizeof(ws_peer->mask));
		buffered_socket_read_exactly(ws_peer->bs, ws_peer->length, ws_get_payload, ws_peer);
	} else {
		if (len < 0) {
			log_peer_err(&ws_peer->peer, "Error while reading websocket mask!\n");
		}
		free_websocket_peer(ws_peer);
	}
}

static void read_mask_or_payload(struct websocket_peer *ws_peer)
{
	if (ws_peer->ws_flags.mask == 1) {
		buffered_socket_read_exactly(ws_peer->bs, sizeof(ws_peer->mask), ws_get_mask, ws_peer);
	} else {
		buffered_socket_read_exactly(ws_peer->bs, ws_peer->length, ws_get_payload, ws_peer);
	}
}

static void ws_get_length16(void *context, char *buf, ssize_t len)
{
	struct websocket_peer *ws_peer = (struct websocket_peer *)context;

	if (likely(len > 0)) {
		uint16_t field;
		memcpy(&field, buf, sizeof(field));
		field = jet_be16toh(field);
		ws_peer->length = field;
		read_mask_or_payload(ws_peer);
	} else {
		if (len < 0) {
			log_peer_err(&ws_peer->peer, "Error while reading websocket 16 bit length!\n");
		}
		free_websocket_peer(ws_peer);
	}
}

static void ws_get_length64(void *context, char *buf, ssize_t len)
{
	struct websocket_peer *ws_peer = (struct websocket_peer *)context;

	if (likely(len > 0)) {
		uint64_t field;
		memcpy(&field, buf, sizeof(field));
		field = jet_be64toh(field);
		ws_peer->length = field;
		read_mask_or_payload(ws_peer);
	} else {
		if (len < 0) {
			log_peer_err(&ws_peer->peer, "Error while reading websocket 64 bit length!\n");
		}
		free_websocket_peer(ws_peer);
	}
}

static void ws_get_first_length(void *context, char *buf, ssize_t len)
{
	struct websocket_peer *ws_peer = (struct websocket_peer *)context;

	if (likely(len > 0)) {
		uint8_t field;
		memcpy(&field, buf, sizeof(field));
		if ((field & WS_MASK_SET) == WS_MASK_SET) {
			ws_peer->ws_flags.mask = 1;
		} else {
			ws_peer->ws_flags.mask = 0;
		}
		field = field & ~WS_MASK_SET;
		if (field < 126) {
			ws_peer->length = field;
			read_mask_or_payload(ws_peer);
		} else if (field == 126) {
			buffered_socket_read_exactly(ws_peer->bs, 2, ws_get_length16, ws_peer);
		} else {
			buffered_socket_read_exactly(ws_peer->bs, 8, ws_get_length64, ws_peer);
		}
	} else {
		if (len < 0) {
			log_peer_err(&ws_peer->peer, "Error while reading websocket first length!\n");
		}
		free_websocket_peer(ws_peer);
	}
}

static void ws_get_header(void *context, char *buf, ssize_t len)
{
	struct websocket_peer *ws_peer = (struct websocket_peer *)context;

	if (likely(len > 0)) {
		uint8_t field;
		memcpy(&field, buf, sizeof(field));
		if ((field & WS_HEADER_FIN) == WS_HEADER_FIN) {
			ws_peer->ws_flags.fin = 1;
		} else {
			ws_peer->ws_flags.fin = 0;
		}

		static const uint8_t OPCODE_MASK = 0x0f;
		field = field & OPCODE_MASK;
		ws_peer->ws_flags.opcode = field;
		buffered_socket_read_exactly(ws_peer->bs, 1, ws_get_first_length, ws_peer);

	} else {
		if (len < 0) {
			log_peer_err(&ws_peer->peer, "Error while reading websocket header!\n");
		}
		free_websocket_peer(ws_peer);
	}
}

static void init_websocket_peer(struct websocket_peer *ws_peer, struct buffered_socket *bs)
{
	init_peer(&ws_peer->peer);
	ws_peer->peer.send_message = ws_send_message;
	ws_peer->peer.close = close_websocket_peer;
	ws_peer->bs = bs;
	buffered_socket_set_error(bs, free_websocket_peer_on_error, ws_peer);
	buffered_socket_read_exactly(ws_peer->bs, 1, ws_get_header, ws_peer);
}

struct websocket_peer *alloc_websocket_peer(struct buffered_socket *bs)
{
	struct websocket_peer *ws_peer = calloc(1, sizeof(*ws_peer));
	if (ws_peer == NULL) {
		return NULL;
	}

	init_websocket_peer(ws_peer, bs);
	return ws_peer;
}
