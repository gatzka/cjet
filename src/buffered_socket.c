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
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>

#include "buffered_socket.h"
#include "compiler.h"
#include "eventloop.h"
#include "linux/peer_testing.h"
#include "log.h"
#include "util.h"

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

static enum callback_return on_error(union io_context *context)
{
	struct io_event *ev = container_of(context, struct io_event, context);
	ev->loop->remove(ev);

	struct buffered_socket *bs = container_of(ev, struct buffered_socket, ev);
	bs->error(bs->error_context);

	return CONTINUE_LOOP;
}

static enum callback_return write_msg(union io_context *context)
{
	struct io_event *ev = container_of(context, struct io_event, context);
	struct buffered_socket *bs = container_of(ev, struct buffered_socket, ev);

	int ret = send_buffer(bs);
	if (unlikely(ret < 0)) {
		on_error(context);
	}
	return CONTINUE_LOOP;
}

int buffered_socket_init(struct buffered_socket *bs, int fd, struct eventloop *loop, void (*error)(void *error_context), void *error_context)
{
	bs->ev.context.fd = fd;
	bs->ev.error_function = on_error;
	bs->ev.read_function = NULL;
	bs->ev.write_function = write_msg;
	bs->ev.loop = loop;

	bs->to_write = 0;
	bs->read_ptr = bs->read_buffer;
	bs->examined_ptr = bs->read_buffer;
	bs->write_ptr = bs->read_buffer;

	bs->error = error;
	bs->error_context = error_context;

	if (loop->add(&bs->ev) == ABORT_LOOP) {
		error(error_context);
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
