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

#ifndef CJET_BUFFERED_SOCKET_H
#define CJET_BUFFERED_SOCKET_H

#include <stddef.h>

#include "eventloop.h"
#include "generated/cjet_config.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IO_WOULD_BLOCK -1
#define IO_ERROR -2
#define IO_TOOMUCHDATA -3

union reader_context {
	const char *ptr;
	size_t num;
};

struct buffered_socket {
	struct io_event ev;
	unsigned int to_write;
	char *read_ptr;
	char *examined_ptr;
	char *write_ptr;
	char *write_buffer_ptr;
	char read_buffer[CONFIG_MAX_MESSAGE_SIZE];
	char write_buffer[CONFIG_MAX_WRITE_BUFFER_SIZE];
	ssize_t (*reader)(struct buffered_socket *bs, union reader_context reader_context, char **read_ptr);
	union reader_context reader_context;
	void (*read_callback)(void *context, char *buf, ssize_t len);
	void *read_callback_context;
	void (*error)(void *error_context);
	void *error_context;
};

struct io_vector {
	const void *iov_base;
	size_t iov_len;
};

void buffered_socket_init(struct buffered_socket *bs, int fd, struct eventloop *loop, void (*error)(void *error_context), void *error_context);
int buffered_socket_writev(struct buffered_socket *bs, struct io_vector *io_vec, unsigned int count);

int read_exactly(struct buffered_socket *bs, size_t num, void (*read_callback)(void *context, char *buf, ssize_t len), void *context);
int read_until(struct buffered_socket *bs, const char *delim, void (*read_callback)(void *context, char *buf, ssize_t len), void *context);

#ifdef __cplusplus
}
#endif

#endif
