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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "alloc.h"
#include "buffered_socket.h"
#include "compiler.h"
#include "error_codes.h"
#include "eventloop.h"
#include "jet_string.h"
#include "log.h"
#include "socket.h"
#include "util.h"

static int send_buffer(struct buffered_socket *bs)
{
	uint8_t *write_buffer_ptr = bs->write_buffer;
	while (bs->to_write != 0) {
		cjet_ssize_t written = socket_writev_with_prefix(bs->ev.sock, write_buffer_ptr, bs->to_write, NULL, 0);

		if (unlikely(written == -1)) {
			enum cjet_system_error err = get_socket_error();
			if (unlikely((err != resource_unavailable_try_again) &&
						 (err != operation_would_block))) {
				log_err("unexpected %s error: %s!", "write", get_socket_error_msg(err));
				return -1;
			} else {
				memmove(bs->write_buffer, write_buffer_ptr, bs->to_write);
				return 0;
			}
		}
		write_buffer_ptr += written;
		bs->to_write -= written;
	}
	return 0;
}

/**
 * @brief go_reading reads until thre reader()-function returns an error or the read_callback() closes the buffered_socket.
 * @param bs The buffered_socket to operate on.
 * @return 0 if the buffered_socket was closed either by the peer or in the read callback of the buffered_socket.
 * @return BS_IO_WOULD_BLOCK is returned if the internal buffer could not be filled but the
 * eventloop shall try filling the buffer later on if data is available.
 * @return BS_IO_ERROR is return if something illegal happened on the underlying socket.
 * @return BS_IO_TOOMUCHDATA is returned if more data is requested in ctx.num than the
 * size of the internal read buffer.
 */
static int go_reading(struct buffered_socket *bs)
{
	while (1) {
		uint8_t *buffer;
		cjet_ssize_t len = bs->reader(bs, bs->reader_context, &buffer);
		if (unlikely(len < 0)) {
			return (int)len;
		} else {
			int ret = bs->read_callback(bs->read_callback_context, buffer, len);
			if (unlikely((len == 0) || (ret == BS_CLOSED))) {
				return 0;
			}
		}
	}
}

static enum eventloop_return error_function(struct io_event *ev)
{
	struct buffered_socket *bs = container_of(ev, struct buffered_socket, ev);
	bs->error(bs->error_context);
	return EL_CONTINUE_LOOP;
}

static enum eventloop_return read_function(struct io_event *ev)
{
	struct buffered_socket *bs = container_of(ev, struct buffered_socket, ev);
	int ret = go_reading(bs);
	if (unlikely((ret < 0) && (ret != BS_IO_WOULD_BLOCK))) {
		error_function(ev);
	}
	if (ret == 0) {
		return EL_EVENT_REMOVED;
	} else {
		return EL_CONTINUE_LOOP;
	}
}

static enum eventloop_return write_function(struct io_event *ev)
{
	struct buffered_socket *bs = container_of(ev, struct buffered_socket, ev);

	int ret = send_buffer(bs);
	if (unlikely(ret < 0)) {
		error_function(ev);
	}
	return EL_CONTINUE_LOOP;
}

static int copy_single_buffer(struct buffered_socket *bs, const char *buf, size_t to_copy)
{
	size_t free_space_in_buf = CONFIG_MAX_WRITE_BUFFER_SIZE - bs->to_write;
	if (unlikely(to_copy > free_space_in_buf)) {
		log_err("not enough space left in write buffer! %zu bytes of %i left", free_space_in_buf, CONFIG_MAX_WRITE_BUFFER_SIZE);
		return -1;
	}

	uint8_t *write_buffer_ptr = bs->write_buffer + bs->to_write;
	memcpy(write_buffer_ptr, buf, to_copy);
	bs->to_write += to_copy;
	return 0;
}

static int copy_iovec_to_write_buffer(struct buffered_socket *bs, const struct socket_io_vector *io_vec,
                                      unsigned int count, size_t iovec_written)
{
	for (unsigned int i = 0; i < count; i++) {
		if (iovec_written < io_vec[i].iov_len) {
			const char *buffer_start = (const char *)io_vec[i].iov_base + iovec_written;
			size_t to_copy = io_vec[i].iov_len - iovec_written;
			if (unlikely(copy_single_buffer(bs, buffer_start, to_copy) < 0)) {
				return -1;
			}
			iovec_written = 0;
		} else {
			iovec_written -= io_vec[i].iov_len;
		}
	}
	return 0;
}

static inline size_t free_space(const struct buffered_socket *bs)
{
	return (size_t)(&(bs->read_buffer[CONFIG_MAX_MESSAGE_SIZE]) - bs->write_ptr);
}

static inline size_t unread_bytes(const struct buffered_socket *bs)
{
	return (size_t)(bs->write_ptr - bs->read_ptr);
}

static void reorganize_read_buffer(struct buffered_socket *bs)
{
	size_t unread = unread_bytes(bs);
	if (unread != 0) {
		memmove(bs->read_buffer, bs->read_ptr, unread);
		bs->write_ptr = bs->read_buffer + unread;
	} else {
		bs->write_ptr = bs->read_buffer;
	}
	bs->read_ptr = bs->read_buffer;
}

static cjet_ssize_t fill_buffer(struct buffered_socket *bs, size_t count)
{
	if (unlikely(free_space(bs) < count)) {
		reorganize_read_buffer(bs);
		if (unlikely(free_space(bs) < count)) {
		  log_err("remaining read buffer too small (%zu bytes) to fulfill request (%zu bytes)!\n", free_space(bs), count);
			return BS_IO_TOOMUCHDATA;
		}
	}
	cjet_ssize_t read_length = socket_read(bs->ev.sock, bs->write_ptr, free_space(bs));
	if (unlikely(read_length == 0)) {
		return BS_PEER_CLOSED;
	}
	if (read_length == -1) {
		enum cjet_system_error err = get_socket_error();
		if (unlikely((err != resource_unavailable_try_again) &&
					 (err != operation_would_block))) {
			log_err("unexpected %s error: %s!", "read", get_socket_error_msg(err));
			return BS_IO_ERROR;
		}
		return BS_IO_WOULD_BLOCK;
	}
	bs->write_ptr += read_length;
	return read_length;
}

/**
 * @brief Special reader function to read exactly n (ctx.num) bytes.
 * 
 * This function immediately returns if the internal read buffer contains enough data
 * to fullfil the request. Otherwise, it tries to fill the internal read buffer. If
 * the latter is not able to fill the read buffer enough, the function returns with
 * IO_WOULD_BLOCK.
 * 
 * @param bs The buffered_socket to operate on
 * @param ctx ctx.num must contain the number of bytes this function call shall read.
 * @param read_ptr This parameter should be considered a return value (out parameter)
 * and is set to the position where the n bytes can be read from if the function returns
 * successfully.
 * 
 * @return A value greater then zero signals success. The number of requested bytes is
 * returned.
 * @return BS_IO_WOULD_BLOCK is returned if the internal buffer could not be filled but the
 * eventloop shall try filling the buffer later on if data is available.
 * @return BS_IO_ERROR is return if something illegal happened on the underlying socket.
 * @return BS_IO_TOOMUCHDATA is returned if more data is requested in ctx.num than the
 * size of the internal read buffer.
 * @return BS_PEER_CLOSED is returned if the socket peer closed the underlying connection
 * and no more data is can be expected to read.
 */
static cjet_ssize_t get_read_ptr(struct buffered_socket *bs, union buffered_socket_reader_context ctx, uint8_t **read_ptr)
{
	size_t count = ctx.num;
	while (1) {
		size_t bytes_in_buffer = unread_bytes(bs);
		if (bytes_in_buffer >= count) {
			*read_ptr = bs->read_ptr;
			bs->read_ptr += count;
			return count;
		}

		cjet_ssize_t number_of_bytes_read = fill_buffer(bs, count - bytes_in_buffer);
		if (number_of_bytes_read <= 0) {
			return number_of_bytes_read;
		}
	}
}

/**
 * @brief Special reader function to until a delimiter sequence string is found.
 * 
 * This function immediately returns if the internal read buffer contains the 
 * sequence string specified in ctx.ptr. Otherwise, it tries to fill the internal
 * read buffer. If the latter is not able to fill the read buffer enough,
 * the function returns with IO_WOULD_BLOCK.
 * 
 * @param bs The buffered_socket to operate on.
 * @param ctx ctx.ptr must point to a zero terminated sequence string.
 * @param read_ptr This parameter should be considered a return value (out parameter)
 * and is set to the position where the string including the delimiter stringcan be
 * read from if the function returns successfully.
 * 
 * @return A value greater then zero signals success. The number of bytes including
 * the delimiter string is returned.
 * @return BS_IO_WOULD_BLOCK is returned if the internal buffer could not be filled but the
 * eventloop shall try filling the buffer later on if data is available.
 * @return BS_IO_ERROR is return if something illegal happened on the underlying socket.
 * @return BS_IO_TOOMUCHDATA is returned if the delimiter is not found in the completly 
 * filled internal read buffer.
 * @return BS_PEER_CLOSED is returned if the socket peer closed the underlying connection
 * and no more data is can be expected to read.
 */
static cjet_ssize_t internal_read_until(struct buffered_socket *bs, union buffered_socket_reader_context ctx, uint8_t **read_ptr)
{
	const uint8_t *haystack = bs->read_ptr;
	const char *needle = ctx.ptr;
	size_t needle_length = strlen(needle);
	while (1) {
		uint8_t *found = jet_memmem(haystack, unread_bytes(bs), needle, needle_length);
		if (found != NULL) {
			*read_ptr = bs->read_ptr;
			ptrdiff_t diff = (found + needle_length) - bs->read_ptr;
			bs->read_ptr += diff;
			return diff;
		} else {
			cjet_ssize_t number_of_bytes_read = fill_buffer(bs, 1);
			haystack = bs->read_ptr;
			if (number_of_bytes_read <= 0) {
				return number_of_bytes_read;
			}
		}
	}
}

void buffered_socket_release(void *this_ptr)
{
	cjet_free(this_ptr);
}

struct buffered_socket *buffered_socket_acquire(void)
{
	return (struct buffered_socket *)cjet_malloc(sizeof(struct buffered_socket));
}

void buffered_socket_set_error(void *this_ptr, void (*error)(void *error_context), void *error_context)
{
	struct buffered_socket *bs = (struct buffered_socket *)this_ptr;
	bs->error = error;
	bs->error_context = error_context;
}

void buffered_socket_init(struct buffered_socket *bs, socket_type sock, struct eventloop *loop,
                          void (*error)(void *error_context), void *error_context)
{
	bs->ev.sock = sock;
	bs->ev.error_function = error_function;
	bs->ev.read_function = read_function;
	bs->ev.write_function = write_function;
	bs->ev.loop = loop;

	bs->to_write = 0;
	bs->read_ptr = bs->read_buffer;
	bs->write_ptr = bs->read_buffer;

	bs->reader = NULL;
	bs->error = error;
	bs->error_context = error_context;
}

int buffered_socket_close(void *context)
{
	struct buffered_socket *bs = (struct buffered_socket *)context;
	bs->ev.loop->remove(bs->ev.loop->this_ptr, &bs->ev);
	int ret = socket_close(bs->ev.sock);
	buffered_socket_release(bs);
	return ret;
}

int buffered_socket_writev(void *this_ptr, struct socket_io_vector *io_vec, unsigned int count)
{
	struct buffered_socket *bs = (struct buffered_socket *)this_ptr;
	size_t to_write = bs->to_write;

	for (unsigned int i = 0; i < count; i++) {
		to_write += io_vec[i].iov_len;
	}

	cjet_ssize_t sent = socket_writev_with_prefix(bs->ev.sock, bs->write_buffer, bs->to_write, io_vec, count);
	if (likely(sent == (cjet_ssize_t)to_write)) {
		return 0;
	}

	size_t written = 0;
	if (sent > 0) {
		written = (size_t)sent;
	}

	if (unlikely(sent == -1)) {
		enum cjet_system_error err = get_socket_error();
		if (unlikely((err != resource_unavailable_try_again) &&
					 (err != operation_would_block))) {
			log_err("unexpected %s error: %s!", "write", get_socket_error_msg(err));
			return -1;
		}
	}

	size_t io_vec_written;
	if (written <= bs->to_write) {
		bs->to_write -= written;
		memmove(bs->write_buffer, bs->write_buffer + written, bs->to_write);
		io_vec_written = 0;
	} else {
		io_vec_written = written - bs->to_write;
		bs->to_write = 0;
	}
	if (unlikely(copy_iovec_to_write_buffer(bs, io_vec, count, io_vec_written) < 0)) {
		return -1;
	}

	if (sent == -1) {
		return 0;
	}

	/*
	 * The write call didn't block, but only wrote parts of the
	 * messages. Try to send the rest.
	 */
	return send_buffer(bs);
}

int buffered_socket_read_exactly(void *this_ptr, size_t num,
                                 enum bs_read_callback_return (*read_callback)(void *context, uint8_t *buf, size_t len),
                                 void *callback_context)
{
	struct buffered_socket *bs = (struct buffered_socket *)this_ptr;
	union buffered_socket_reader_context ctx = {.num = num};
	bool first_run = (bs->reader == NULL);
	bs->reader = get_read_ptr;
	bs->reader_context = ctx;
	bs->read_callback = read_callback;
	bs->read_callback_context = callback_context;

	if (likely(!first_run)) {
		return 0;
	}

	if (bs->ev.loop->add(bs->ev.loop->this_ptr, &bs->ev) == EL_ABORT_LOOP) {
		return -1;
	} else {
		int ret = go_reading(bs);
		if (likely(ret == BS_IO_WOULD_BLOCK)) {
			return 0;
		} else if (ret < 0) {
			error_function(&bs->ev);
		}
		return 0;
	}
}

int buffered_socket_read_until(void *this_ptr, const char *delim,
                               enum bs_read_callback_return (*read_callback)(void *context, uint8_t *buf, size_t len),
                               void *callback_context)
{
	struct buffered_socket *bs = (struct buffered_socket *)this_ptr;
	union buffered_socket_reader_context ctx = {.ptr = delim};
	bool first_run = (bs->reader == NULL);
	bs->reader = internal_read_until;
	bs->reader_context = ctx;
	bs->read_callback = read_callback;
	bs->read_callback_context = callback_context;

	if (likely(!first_run)) {
		return 0;
	}

	if (bs->ev.loop->add(bs->ev.loop->this_ptr, &bs->ev) == EL_ABORT_LOOP) {
		return -1;
	} else {
		int ret = go_reading(bs);
		if (likely(ret == BS_IO_WOULD_BLOCK)) {
			return 0;
		} else if (ret < 0) {
			error_function(&bs->ev);
		}
		return 0;
	}
}
