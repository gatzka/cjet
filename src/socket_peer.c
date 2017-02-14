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

#include <arpa/inet.h>
#include <stdint.h>
#include <unistd.h>

#include "alloc.h"
#include "buffered_reader.h"
#include "compiler.h"
#include "jet_endian.h"
#include "log.h"
#include "parse.h"
#include "router.h"
#include "socket_peer.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

static void free_jet_peer(struct socket_peer *p)
{
	free_peer_resources(&p->peer);
	p->br.close(p->br.this_ptr);
	cjet_free(p);
}

void free_peer_on_error(void *context)
{
	struct socket_peer *p = (struct socket_peer *)context;
	free_jet_peer(p);
}

static void close_jet_peer(struct peer *p)
{
	struct socket_peer *s_peer = container_of(p, struct socket_peer, peer);
	free_jet_peer(s_peer);
}

static enum bs_read_callback_return read_msg_length(void *context, uint8_t *buf, size_t len);

static enum bs_read_callback_return read_msg(void *context, uint8_t *buf, size_t len)
{
	struct socket_peer *p = (struct socket_peer *)context;

	if (unlikely(len == 0)) {
		free_jet_peer(p);
		return BS_CLOSED;
	}

	int ret = parse_message((const char *)buf, len, &p->peer);
	if (unlikely(ret < 0)) {
		free_jet_peer(p);
		return BS_CLOSED;
	}

	struct buffered_reader *br = &p->br;
	br->read_exactly(br->this_ptr, 4, read_msg_length, p);
	return BS_OK;
}

static enum bs_read_callback_return read_msg_length(void *context, uint8_t *buf, size_t len)
{
	struct socket_peer *p = (struct socket_peer *)context;

	if (unlikely(len == 0)) {
		free_jet_peer(p);
		return BS_CLOSED;
	}

	uint32_t message_length;
	memcpy(&message_length, buf, len);
	message_length = ntohl(message_length);

	struct buffered_reader *br = &p->br;
	br->read_exactly(br->this_ptr, message_length, read_msg, p);
	return BS_OK;
}

static int send_message(const struct peer *p, char *rendered, size_t len)
{
	uint32_t message_length = htonl(len);
	struct socket_io_vector iov[2];
	iov[0].iov_base = &message_length;
	iov[0].iov_len = sizeof(message_length);
	iov[1].iov_base = rendered;
	iov[1].iov_len = len;
	const struct socket_peer *s_peer = const_container_of(p, struct socket_peer, peer);

	const struct buffered_reader *br = &s_peer->br;
	return br->writev(br->this_ptr, iov, ARRAY_SIZE(iov));
}

void init_socket_peer(struct socket_peer *p, struct buffered_reader *reader, bool is_local_connection)
{
	struct buffered_socket *bs = (struct buffered_socket *)reader->this_ptr;

	init_peer(&p->peer, is_local_connection, bs->ev.loop);
	p->peer.send_message = send_message;
	p->peer.close = close_jet_peer;

	struct buffered_reader *br = &p->br;
	br->this_ptr = reader->this_ptr;
	br->close = reader->close;
	br->read_exactly = reader->read_exactly;
	br->read_until = reader->read_until;
	br->set_error_handler = reader->set_error_handler;
	br->writev = reader->writev;

	br->read_exactly(br->this_ptr, 4, read_msg_length, p);
}

struct socket_peer *alloc_jet_peer(void)
{
	return cjet_malloc(sizeof(struct socket_peer));
}
