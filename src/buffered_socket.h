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
#include <stdint.h>

#include "compiler.h"
#include "eventloop.h"
#include "generated/cjet_config.h"
#include "generated/os_config.h"
#include "socket.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BS_PEER_CLOSED 0
#define BS_IO_WOULD_BLOCK -1
#define BS_IO_ERROR -2
#define BS_IO_TOOMUCHDATA -3

enum bs_read_callback_return {BS_OK, BS_CLOSED};

union buffered_socket_reader_context {
	const char *ptr;
	size_t num;
};

struct buffered_socket {
	struct io_event ev;
	size_t to_write;
	uint8_t *read_ptr;
	uint8_t *write_ptr;
	uint8_t *write_buffer_ptr;
	uint8_t read_buffer[CONFIG_MAX_MESSAGE_SIZE];
	uint8_t write_buffer[CONFIG_MAX_WRITE_BUFFER_SIZE];
	cjet_ssize_t (*reader)(struct buffered_socket *bs, union buffered_socket_reader_context reader_context, uint8_t **read_ptr);
	union buffered_socket_reader_context reader_context;
	enum bs_read_callback_return (*read_callback)(void *context, uint8_t *buf, size_t len);
	void *read_callback_context;
	void (*error)(void *error_context);
	void *error_context;
};

struct buffered_socket *buffered_socket_acquire(void);
void buffered_socket_release(void *this_ptr);

void buffered_socket_init(struct buffered_socket *bs, socket_type sock, struct eventloop *loop, void (*error)(void *error_context), void *error_context);
int buffered_socket_close(void *context);
int buffered_socket_writev(void *this_ptr, struct socket_io_vector *io_vec, unsigned int count);
void buffered_socket_set_error(void *this_ptr, void (*error)(void *error_context), void *error_context);

/**
 * @brief buffered_socket_read_exactly starts an IO operation to read exactly \p num bytes.
 * @param this_ptr The buffered_socket to operate on.
 * @param num The number of bytes buffered_socket shall read before calling \p read_callback.
 * @param read_callback The callback that will be called in case of success or error.
 * @param callback_context The context pointer that will be the first argument of \p read_callback.
 * @return 0 if everything is fine
 * @return -1 if an error occured or the underlying socket connection was closed either by the
 *         peer or inside the \p read_callback function.
 */
int buffered_socket_read_exactly(void *this_ptr, size_t num,
                                 enum bs_read_callback_return (*read_callback)(void *context, uint8_t *buf, size_t len),
                                 void *callback_context);

/**
 * @brief buffered_socket_read_until starts an IO operation to read until \p delim is found.
 * @param this_ptr The buffered_socket to operate on.
 * @param delim The delimiter that will be searched for.
 * @param read_callback The callback that will be called in case of success or error.
 * @param callback_context The context pointer that will be the first argument of \p read_callback.
 * @return 0 if everything is fine,
 * @return -1 if an error occured or the underlying socket connection was closed either by the
 *         peer or inside the read_callback() function.
 */
int buffered_socket_read_until(void *this_ptr, const char *delim,
                               enum bs_read_callback_return (*read_callback)(void *context, uint8_t *buf, size_t len),
                               void *callback_context);

#ifdef __cplusplus
}
#endif

#endif
