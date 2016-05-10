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

#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>

#include "buffered_socket.h"
#include "compiler.h"
#include "eventloop.h"
#include "linux/peer_testing.h"
#include "log.h"
#include "util.h"

#define IO_WOULD_BLOCK -1
#define IO_ERROR -2
#define IO_TOOMUCHDATA -3

static int send_buffer(struct buffered_socket *bs)
{
	char *write_buffer_ptr = bs->write_buffer;
	while (bs->to_write != 0) {
		ssize_t written =
			SEND(bs->ev.context.fd, write_buffer_ptr, bs->to_write, MSG_NOSIGNAL);
		if (unlikely(written == -1)) {
			if (unlikely((errno != EAGAIN) &&
				(errno != EWOULDBLOCK))) {
				log_err("unexpected write error: %s!", strerror(errno));
				return -1;
			}
			memmove(bs->write_buffer, write_buffer_ptr, bs->to_write);
			return 0;
		}
		write_buffer_ptr += written;
		bs->to_write -= written;
	}
	return 0;
}

static int go_reading(struct buffered_socket *bs)
{
	if (unlikely(bs->reader == NULL)) {
		return 0;
	}
	while (1) {
		char *buffer;
		ssize_t len = bs->reader(bs, bs->reader_context, &buffer);
		if (len < 0) {
			if (unlikely(len != IO_WOULD_BLOCK)) {
				return len;
			} else {
				return 0;
			}
		} else {
			bs->read_callback(bs->read_callback_context, buffer, len);
		}
	}
}

static enum callback_return error_function(union io_context *context)
{
	struct io_event *ev = container_of(context, struct io_event, context);
	ev->loop->remove(ev);

	struct buffered_socket *bs = container_of(ev, struct buffered_socket, ev);
	bs->error(bs->error_context);

	return CONTINUE_LOOP;
}

static enum callback_return read_function(union io_context *context)
{
	struct io_event *ev = container_of(context, struct io_event, context);
	struct buffered_socket *bs = container_of(ev, struct buffered_socket, ev);
	int ret = go_reading(bs);
	if (unlikely(ret < 0)) {
		error_function(context);
	}

	return CONTINUE_LOOP;
}

static enum callback_return write_function(union io_context *context)
{
	struct io_event *ev = container_of(context, struct io_event, context);
	struct buffered_socket *bs = container_of(ev, struct buffered_socket, ev);

	int ret = send_buffer(bs);
	if (unlikely(ret < 0)) {
		error_function(context);
	}
	return CONTINUE_LOOP;
}

int buffered_socket_init(struct buffered_socket *bs, int fd, struct eventloop *loop, void (*error)(void *error_context), void *error_context)
{
	bs->ev.context.fd = fd;
	bs->ev.error_function = error_function;
	bs->ev.read_function = read_function;
	bs->ev.write_function = write_function;
	bs->ev.loop = loop;

	bs->to_write = 0;
	bs->read_ptr = bs->read_buffer;
	bs->examined_ptr = bs->read_buffer;
	bs->write_ptr = bs->read_buffer;

	bs->reader = NULL;
	bs->error = error;
	bs->error_context = error_context;

	if (loop->add(&bs->ev) == ABORT_LOOP) {
		return -1;
	} else {
		return 0;
	}
}

static int copy_single_buffer(struct buffered_socket *bs, const char *buf, size_t to_copy)
{
	size_t free_space_in_buf = CONFIG_MAX_WRITE_BUFFER_SIZE - bs->to_write;
	if (unlikely(to_copy > free_space_in_buf)) {
		log_err("not enough space left in write buffer! %zu bytes of %i left", free_space_in_buf, CONFIG_MAX_WRITE_BUFFER_SIZE);
		return -1;
	}

	char *write_buffer_ptr = bs->write_buffer + bs->to_write;
	memcpy(write_buffer_ptr, buf, to_copy);
	bs->to_write += to_copy;
	return 0;
}

static int copy_iovec_to_write_buffer(struct buffered_socket *bs, const struct io_vector *io_vec, unsigned int count, size_t iovec_written)
{
	for (unsigned int i = 0; i < count; i++) {
		if (iovec_written < io_vec[i].iov_len) {
			const char *buffer_start = (const char *)io_vec[i].iov_base + iovec_written;
			size_t to_copy = io_vec[i].iov_len - iovec_written;
			if (unlikely(copy_single_buffer(bs, buffer_start, to_copy) < 0)) {
				return -1;
			}
			iovec_written = 0;
		}
	}
	return 0;
}

int buffered_socket_writev(struct buffered_socket *bs, const struct io_vector *io_vec, unsigned int count)
{
	struct iovec iov[count + 1];
	size_t to_write = bs->to_write;

	iov[0].iov_base = bs->write_buffer;
	iov[0].iov_len = bs->to_write;
/*
 * This pragma is used because iov_base is not declared const.
 * Nevertheless, I want to have the parameter io_vec const. Therefore I
 * selectively disabled the cast-qual warning.
 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
	for (unsigned int i = 0; i < count; i++) {
		iov[i].iov_base = (void *)io_vec->iov_base;
		iov[i].iov_len = io_vec->iov_len;
		to_write += io_vec->iov_len;
	}
#pragma GCC diagnostic pop

	ssize_t sent = WRITEV(bs->ev.context.fd, iov, sizeof(iov) / sizeof(struct iovec));
	if (likely(sent == (ssize_t)to_write)) {
		return 0;
	}

	size_t written = 0;
	if (sent > 0) {
		written = (size_t)sent;
	}

	if (unlikely((sent == -1) &&
		((errno != EAGAIN) && (errno != EWOULDBLOCK)))) {
		log_err("unexpected %s error: %s!\n", "write",
			strerror(errno));
		return -1;
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

static inline ptrdiff_t unread_space(const struct buffered_socket *bs)
{
	return &(bs->read_buffer[CONFIG_MAX_MESSAGE_SIZE]) - bs->read_ptr;
}

static inline ptrdiff_t free_space(const struct buffered_socket *bs)
{
	return &(bs->read_buffer[CONFIG_MAX_MESSAGE_SIZE]) - bs->write_ptr;
}

static void reorganize_read_buffer(struct buffered_socket *bs)
{
	ptrdiff_t unread = bs->write_ptr - bs->read_ptr;
	if (unread != 0) {
		memmove(bs->read_buffer, bs->read_ptr, (size_t)unread);
		bs->write_ptr = bs->read_buffer + unread;
	} else {
		bs->write_ptr = bs->read_buffer;
	}
	bs->read_ptr = bs->read_buffer;
}

static ssize_t get_read_ptr(struct buffered_socket *bs, union reader_context ctx, char **read_ptr)
{
	size_t count = ctx.num;
	if (unlikely((ptrdiff_t)count > unread_space(bs))) {
		reorganize_read_buffer(bs);
		if (unlikely((ptrdiff_t)count > unread_space(bs))) {
			log_err("peer asked for too much data: %zu!\n", count);
		}
		return IO_TOOMUCHDATA;
	}
	while (1) {
		ptrdiff_t diff = bs->write_ptr - bs->read_ptr;
		if (diff >= (ptrdiff_t)count) {
			*read_ptr = bs->read_ptr;
			bs->read_ptr += count;
			return diff;
		}

		ssize_t read_length = READ(bs->ev.context.fd, bs->write_ptr, (size_t)free_space(bs));
		if (unlikely(read_length == 0)) {
			return 0;
		}
		if (read_length == -1) {
			if (unlikely((errno != EAGAIN) && (errno != EWOULDBLOCK))) {
				log_err("unexpected %s error: %s!\n", "read", strerror(errno));
				*read_ptr = NULL;
				return IO_ERROR;
			}
			return IO_WOULD_BLOCK;
		}
		bs->write_ptr += read_length;
	}
}

int read_exactly(struct buffered_socket *bs, size_t num, void (*read_callback)(void *context, char *buf, ssize_t len), void *context)
{
	union reader_context ctx = { .num = num };
	bool first_run =  (bs->reader == NULL);
	bs->reader = get_read_ptr;
	bs->reader_context = ctx;
	bs->read_callback = read_callback;
	bs->read_callback_context = context;

	if (likely(!first_run)) {
		return 0;
	}

	return go_reading(bs);
}
