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
#include <unistd.h>

#include "compiler.h"
#include "eventloop.h"
#include "http_server.h"
#include "linux/peer_testing.h"
#include "peer.h"
#include "socket_peer.h"
#include "websocket_peer.h"

static enum callback_return free_peer_on_error(const struct eventloop *loop, union io_context *context)
{
	struct io_event *ev = container_of(context, struct io_event, context);
	struct socket_peer *p = container_of(ev, struct socket_peer, ev);
	struct ws_peer *ws_peer = container_of(p, struct ws_peer, s_peer);
	free_wsjet_peer(loop, ws_peer);
	return CONTINUE_LOOP;
}

static int init_websocket_peer(const struct eventloop *loop, struct ws_peer *p, int fd)
{
	init_peer(&p->s_peer.peer);
	p->s_peer.ev.context.fd = fd;
	p->s_peer.ev.read_function = handle_ws_upgrade;
	p->s_peer.ev.write_function = write_msg;
	p->s_peer.ev.error_function = free_peer_on_error;

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

void free_wsjet_peer(const struct eventloop *loop, struct ws_peer *p)
{
	int fd = p->s_peer.ev.context.fd;
	loop->remove(&p->s_peer.ev);
	free_peer(&p->s_peer.peer);
	free(p);
	close(fd);
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
