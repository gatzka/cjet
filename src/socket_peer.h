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

#ifndef CJET_SOCKET_PEER_H
#define CJET_SOCKET_PEER_H

#include <stdint.h>
#include <stddef.h>

#include "eventloop.h"
#include "peer.h"

#define READ_MSG_LENGTH 0
#define READ_MSG 1
#define READ_CR 2

#define IO_CLOSE -1
#define IO_WOULD_BLOCK -2
#define IO_ERROR -3
#define IO_TOOMUCHDATA -4
#define IO_BUFFERTOOSMALL -5

struct socket_peer {
	struct peer peer;
	struct io_event ev;
	int op;
	unsigned int to_write;
	uint32_t msg_length;
	size_t write_buffer_size;
	char *read_ptr;
	char *examined_ptr;
	char *write_ptr;
	char *write_buffer_ptr;
	char read_buffer[CONFIG_MAX_MESSAGE_SIZE];
	char write_buffer[CONFIG_MAX_WRITE_BUFFER_SIZE];
};

struct socket_peer *alloc_jet_peer(const struct eventloop *loop, int fd);
int send_message(struct peer *p, const char *rendered, size_t len);

enum callback_return write_msg(union io_context *context);
ssize_t get_read_ptr(struct socket_peer *p, unsigned int count, char **read_ptr);
ssize_t read_cr_lf_line(struct socket_peer *p, const char **read_ptr);
void reorganize_read_buffer(struct socket_peer *p); // TODO: avoid that call, reorganize internally.

#endif
