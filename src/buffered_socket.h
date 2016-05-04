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

struct buffered_socket {
	struct io_event ev;
	unsigned int to_write;
	char *read_ptr;
	char *examined_ptr;
	char *write_ptr;
	char *write_buffer_ptr;
	char read_buffer[CONFIG_MAX_MESSAGE_SIZE];
	char write_buffer[CONFIG_MAX_WRITE_BUFFER_SIZE];
};

enum buffered_socket_error {
	BS_OK,
	BS_ERROR
};

void buffered_socket_init(struct buffered_socket *bs, int fd, struct eventloop *loop);

enum buffered_socket_error read_at_least(const struct buffered_socket *bs, size_t num, read_callback, void *context);
enum buffered_socket_error read_until(const struct buffered_socket *bs, const char *delim, read_callback, void *context);

#endif
