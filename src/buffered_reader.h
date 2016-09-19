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

#ifndef BUFFERED_READER_H
#define BUFFERED_READER_H

#include <stddef.h>
#include <stdint.h>

#include "buffered_socket.h"

typedef enum bs_read_callback_return (*read_handler)(void *context, uint8_t *buf, size_t len);
typedef void (*error_handler)(void *error_context);

struct buffered_reader {
	void *this_ptr;
	int (*read_exactly)(void *this_ptr, size_t num, read_handler handler, void *handler_context);
	int (*read_until)(void *this_ptr, const char *delim, read_handler handler, void *handler_context);
	int (*writev)(void *this_ptr, struct buffered_socket_io_vector *io_vec, unsigned int count);
	int (*close)(void *this_ptr);
	void(*set_error_handler)(void *this_ptr, error_handler handler, void *error_context);
};

#endif
