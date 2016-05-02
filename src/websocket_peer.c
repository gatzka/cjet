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

static void free_websocket_peer(const struct eventloop *loop, struct ws_peer *p)
{
	int fd = p->s_peer.ev.context.fd;
	loop->remove(&p->s_peer.ev);
	free_peer(&p->s_peer.peer);
	free(p);
	close(fd);
}

static enum callback_return free_websocket_peer_on_error(const struct eventloop *loop, union io_context *context)
{
	struct io_event *ev = container_of(context, struct io_event, context);
	struct socket_peer *p = container_of(ev, struct socket_peer, ev);
	struct ws_peer *ws_peer = container_of(p, struct ws_peer, s_peer);
	free_websocket_peer(loop, ws_peer);
	return CONTINUE_LOOP;
}

static void close_websocket_peer(struct peer *p)
{
	struct socket_peer *s_peer = container_of(p, struct socket_peer, peer);
	struct ws_peer *ws_peer = container_of(s_peer, struct ws_peer, s_peer);
	free_websocket_peer(s_peer->ev.loop, ws_peer);
}

static int ws_send_frame(struct peer *p, bool shall_mask, uint32_t mask, const char *payload, size_t length)
{
	struct socket_peer *s_peer = container_of(p, struct socket_peer, peer);
	struct ws_peer *ws_peer = container_of(s_peer, struct ws_peer, s_peer);

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

	return send_ws_response(ws_peer, ws_header, header_index, payload, length);
}

static int ws_send_message(struct peer *p, const char *rendered, size_t len)
{
	return ws_send_frame(p, false, 0x00, rendered, len);
}

static int init_websocket_peer(const struct eventloop *loop, struct ws_peer *p, int fd)
{
	init_peer(&p->s_peer.peer);
	p->s_peer.peer.send_message = ws_send_message;
	p->s_peer.peer.close = close_websocket_peer;
	
	p->s_peer.ev.context.fd = fd;
	p->s_peer.ev.read_function = handle_ws_upgrade;
	p->s_peer.ev.write_function = write_msg;
	p->s_peer.ev.error_function = free_websocket_peer_on_error;
	p->s_peer.ev.loop = loop;

	p->s_peer.op = READ_MSG_LENGTH;
	p->s_peer.to_write = 0;
	p->s_peer.read_ptr = p->s_peer.read_buffer;
	p->s_peer.examined_ptr = p->s_peer.read_ptr;
	p->s_peer.write_ptr = p->s_peer.read_buffer;

	if (loop->add(loop, &p->s_peer.ev) == ABORT_LOOP) {
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

	if (init_websocket_peer(loop, p, fd) < 0) {
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

int send_ws_response(struct ws_peer *p, const char *header, size_t header_size, const char *payload, size_t payload_size)
{
	struct iovec iov[3];

	iov[0].iov_base = p->s_peer.write_buffer;
	iov[0].iov_len = p->s_peer.to_write;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
	iov[1].iov_base = (void *)header;
	iov[1].iov_len = header_size;
	iov[2].iov_base = (void *)payload;
	iov[2].iov_len = payload_size;
#pragma GCC diagnostic pop

	ssize_t sent = WRITEV(p->s_peer.ev.context.fd, iov, sizeof(iov) / sizeof(struct iovec));
	if (likely(sent == (ssize_t)(header_size + payload_size))) {
		return 0;
	} else {
		return -1;
	}
	// TODO: handle partial writes as below
}
