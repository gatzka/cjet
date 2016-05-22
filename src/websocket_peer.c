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
#include <sys/uio.h>
#include <stdbool.h>
#include <unistd.h>

#include "compiler.h"
#include "eventloop.h"
#include "http_server.h"
#include "jet_endian.h"
#include "linux/peer_testing.h"
#include "peer.h"
#include "socket_peer.h"
#include "websocket_peer.h"

#ifndef ARRAY_SIZE
# define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

static void free_websocket_peer_old(const struct eventloop *loop, struct ws_peer *p)
{
	int fd = p->s_peer.ev.context.fd;
	loop->remove(&p->s_peer.ev);
	free_peer(&p->s_peer.peer);
	free(p);
	close(fd);
}

static enum callback_return free_websocket_peer_on_error_old(union io_context *context)
{
	struct io_event *ev = container_of(context, struct io_event, context);
	struct socket_peer *p = container_of(ev, struct socket_peer, ev);
	struct ws_peer *ws_peer = container_of(p, struct ws_peer, s_peer);
	free_websocket_peer_old(ev->loop, ws_peer);
	return CONTINUE_LOOP;
}

static void close_websocket_peer(struct peer *p)
{
	struct socket_peer *s_peer = container_of(p, struct socket_peer, peer);
	struct ws_peer *ws_peer = container_of(s_peer, struct ws_peer, s_peer);
	free_websocket_peer_old(s_peer->ev.loop, ws_peer);
}

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

static int init_websocket_peer_old(const struct eventloop *loop, struct ws_peer *p, int fd)
{
	init_peer(&p->s_peer.peer);
	p->s_peer.peer.send_message = ws_send_message;
	p->s_peer.peer.close = close_websocket_peer;
	
	p->s_peer.ev.context.fd = fd;
	p->s_peer.ev.read_function = handle_ws_upgrade;
	p->s_peer.ev.write_function = write_msg;
	p->s_peer.ev.error_function = free_websocket_peer_on_error_old;
	p->s_peer.ev.loop = loop;

	p->s_peer.op = READ_MSG_LENGTH;
	p->s_peer.to_write = 0;
	p->s_peer.read_ptr = p->s_peer.read_buffer;
	p->s_peer.examined_ptr = p->s_peer.read_ptr;
	p->s_peer.write_ptr = p->s_peer.read_buffer;

	if (loop->add(&p->s_peer.ev) == ABORT_LOOP) {
		free_peer(&p->s_peer.peer);
		return -1;
	} else {
		return 0;
	}
}

struct ws_peer *alloc_wsjet_peer(const struct eventloop *loop, int fd)
{
	struct ws_peer *p = malloc(sizeof(*p));
	if (unlikely(p == NULL)) {
		return NULL;
	}

	p->current_header_field = HEADER_UNKNOWN;
	p->flags.connection_upgrade = 0;
	p->flags.header_upgrade = 0;
	p->ws_protocol = WS_READING_HEADER;
	http_init(p);

	if (init_websocket_peer_old(loop, p, fd) < 0) {
		free(p);
		return NULL;
	} else {
		return p;
	}
}

int send_ws_upgrade_response(struct ws_peer *p, const char *begin, size_t begin_length, const char *key, size_t key_length, const char *end, size_t end_length)
{
	struct iovec iov[4];

	iov[0].iov_base = p->s_peer.write_buffer;
	iov[0].iov_len = p->s_peer.to_write;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
	iov[1].iov_base = (void *)begin;
	iov[1].iov_len = begin_length;
	iov[2].iov_base = (void *)key;
	iov[2].iov_len = key_length;
	iov[3].iov_base = (void *)end;
	iov[3].iov_len = end_length;
#pragma GCC diagnostic pop

	ssize_t sent = WRITEV(p->s_peer.ev.context.fd, iov, sizeof(iov) / sizeof(struct iovec));
	if (likely(sent == (ssize_t)(begin_length + key_length + end_length))) {
		return 0;
	} else {
		return -1;
	}
	// TODO: handle partial writes as below
}



// TODO: delete old stuff


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

static void read_mask_or_payload(struct websocket_peer *ws_peer)
{
	if (ws_peer->ws_flags.mask == 1) {
		//buffered_socket_read_exactly(ws_peer->bs, sizeof(ws_peer->mask), ws_get_mask, ws_peer);
	} else {
	//	buffered_socket_read_exactly(ws_peer->bs, ws_peer->length), ws_get_payload, ws_peer);
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

			static const uint8_t OPCODE_MASK = 0x0f;
			field = field & OPCODE_MASK;
			ws_peer->ws_flags.opcode = field;
			buffered_socket_read_exactly(ws_peer->bs, 1, ws_get_first_length, ws_peer);
		}

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
