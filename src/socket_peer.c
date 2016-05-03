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

#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "compiler.h"
#include "generated/cjet_config.h"
#include "eventloop.h"
#include "jet_endian.h"
#include "linux/peer_testing.h"
#include "log.h"
#include "parse.h"
#include "router.h"
#include "socket_peer.h"

static inline ptrdiff_t free_space(const struct socket_peer *p)
{
	return &(p->read_buffer[CONFIG_MAX_MESSAGE_SIZE]) - p->write_ptr;
}

static inline ptrdiff_t unread_space(const struct socket_peer *p)
{
	return &(p->read_buffer[CONFIG_MAX_MESSAGE_SIZE]) - p->read_ptr;
}

void reorganize_read_buffer(struct socket_peer *p)
{
	ptrdiff_t unread = p->write_ptr - p->read_ptr;
	if (unread != 0) {
		memmove(p->read_buffer, p->read_ptr, (size_t)unread);
		p->write_ptr = p->read_buffer + unread;
	} else {
		p->write_ptr = p->read_buffer;
	}
	p->read_ptr = p->read_buffer;
}

ssize_t get_read_ptr(struct socket_peer *p, unsigned int count, char **read_ptr)
{
	if (unlikely((ptrdiff_t)count > unread_space(p))) {
		log_err("peer asked for too much data: %u!\n", count);
		*read_ptr = NULL;
		return IO_TOOMUCHDATA;
	}
	while (1) {
		ptrdiff_t diff = p->write_ptr - p->read_ptr;
		if (diff >= (ptrdiff_t)count) {
			*read_ptr = p->read_ptr;
			p->read_ptr += count;
			return diff;
		}

		ssize_t read_length = READ(p->ev.context.fd, p->write_ptr, (size_t)free_space(p));
		if (unlikely(read_length == 0)) {
			*read_ptr = NULL;
			return IO_CLOSE;
		}
		if (read_length == -1) {
			if (unlikely((errno != EAGAIN) && (errno != EWOULDBLOCK))) {
				log_err("unexpected %s error: %s!\n", "read", strerror(errno));
				*read_ptr = NULL;
				return IO_ERROR;
			}
			*read_ptr = NULL;
			return IO_WOULD_BLOCK;
		}
		p->write_ptr += read_length;
	}
	*read_ptr = NULL;
	return IO_ERROR;
}

ssize_t read_cr_lf_line(struct socket_peer *p, const char **read_ptr)
{
	while (1) {
		while (p->examined_ptr < p->write_ptr) {
			if ((p->op == READ_CR) && (*p->examined_ptr == '\n')) {
				*read_ptr = p->read_ptr;
				ptrdiff_t diff = p->examined_ptr - p->read_ptr + 1;
				p->read_ptr += diff;
				p->op = READ_MSG;
				return diff;
			} else {
				p->op = READ_MSG;
			}
			if (*p->examined_ptr == '\r') {
				p->op = READ_CR;
			}
			p->examined_ptr++;
		}

		if (free_space(p) == 0) {
			log_err("Read buffer too small for a complete line!");
			*read_ptr = NULL;
			return IO_BUFFERTOOSMALL;
		}
		ssize_t read_length = READ(p->ev.context.fd, p->write_ptr, (size_t)free_space(p));
		if (unlikely(read_length == 0)) {
			*read_ptr = NULL;
			return IO_CLOSE;
		}
		if (read_length == -1) {
			if (unlikely((errno != EAGAIN) && (errno != EWOULDBLOCK))) {
				log_err("unexpected %s error: %s!\n", "read", strerror(errno));
				*read_ptr = NULL;
				return IO_ERROR;
			}
			*read_ptr = NULL;
			return IO_WOULD_BLOCK;
		}
		p->write_ptr += read_length;
	}
}

static int read_msg_length(struct socket_peer *p)
{
	uint32_t message_length;
	char *message_length_ptr;
	ssize_t ret = get_read_ptr(p, sizeof(message_length), &message_length_ptr);
	if (unlikely(ret <= 0)) {
		if (ret == IO_WOULD_BLOCK) {
			return 0;
		}
	} else {
		memcpy(&message_length, message_length_ptr, sizeof(message_length));
		p->op = READ_MSG;
		p->msg_length = ntohl(message_length);
	}
	return ret;
}

static int read_msg(struct socket_peer *p)
{
	uint32_t message_length = p->msg_length;
	char *message_ptr;
	ssize_t ret = get_read_ptr(p, message_length, &message_ptr);
	if (unlikely(ret <= 0)) {
		if (ret == IO_WOULD_BLOCK) {
			return 0;
		} else {
			return ret;
		}
	} else {
		p->op = READ_MSG_LENGTH;
		ret = parse_message(message_ptr, message_length, &p->peer);
		if (unlikely(ret == -1)) {
			return -1;
		}
		reorganize_read_buffer(p);
		return 1;
	}
}

static enum callback_return handle_all_peer_operations(union io_context *context)
{
	struct io_event *ev = container_of(context, struct io_event, context);
	struct socket_peer *p = container_of(ev, struct socket_peer, ev);
	while (1) {
		int ret;

		switch (p->op) {
		case READ_MSG_LENGTH:
			ret = read_msg_length(p);
			break;

		case READ_MSG:
			ret = read_msg(p);
			break;

		default:
			log_err("Unknown client operation!\n");
			ret = -1;
			break;
		}

		if (unlikely(ret <= 0)) {
			if (unlikely(ret < 0)) {
				p->peer.close(&p->peer);
			}
			return CONTINUE_LOOP;
		}
	}
}

static int send_buffer(struct socket_peer *p)
{
	char *write_buffer_ptr = p->write_buffer;
	while (p->to_write != 0) {
		ssize_t written;
		written =
			SEND(p->ev.context.fd, write_buffer_ptr, p->to_write, MSG_NOSIGNAL);
		if (unlikely(written == -1)) {
			if (unlikely((errno != EAGAIN) &&
				(errno != EWOULDBLOCK))) {
				log_err("unexpected write error: %s!", strerror(errno));
				return -1;
			}
			memmove(p->write_buffer, write_buffer_ptr, p->to_write);
			return 0;
		}
		write_buffer_ptr += written;
		p->to_write -= written;
	}
	return 0;
}

enum callback_return write_msg(union io_context *context)
{
	struct io_event *ev = container_of(context, struct io_event, context);
	struct socket_peer *s_peer = container_of(ev, struct socket_peer, ev);

	int ret = send_buffer(s_peer);
	if (unlikely(ret < 0)) {
		s_peer->peer.close(&s_peer->peer);
	}
	 return CONTINUE_LOOP;
}

static void free_jet_peer(const struct eventloop *loop, struct socket_peer *p)
{
	int fd = p->ev.context.fd;
	loop->remove(&p->ev);
	free_peer(&p->peer);
	free(p);
	close(fd);
}

static enum callback_return free_peer_on_error(union io_context *context)
{
	struct io_event *ev = container_of(context, struct io_event, context);
	struct socket_peer *p = container_of(ev, struct socket_peer, ev);
	free_jet_peer(ev->loop, p);
	return CONTINUE_LOOP;
}

static void close_jet_peer(struct peer *p)
{
	struct socket_peer *s_peer = container_of(p, struct socket_peer, peer);
	free_jet_peer(s_peer->ev.loop, s_peer);
}

static int init_socket_peer(const struct eventloop *loop, struct socket_peer *p, int fd)
{
	init_peer(&p->peer);
	p->peer.send_message = send_message;
	p->peer.close = close_jet_peer;

	p->ev.context.fd = fd;
	p->ev.read_function = handle_all_peer_operations;
	p->ev.write_function = write_msg;
	p->ev.error_function = free_peer_on_error;
	p->ev.loop = loop;

	p->op = READ_MSG_LENGTH;
	p->to_write = 0;
	p->read_ptr = p->read_buffer;
	p->examined_ptr = p->read_ptr;
	p->write_ptr = p->read_buffer;

	if (loop->add(&p->ev) == ABORT_LOOP) {
		free_peer(&p->peer);
		return -1;
	} else {
		return 0;
	}
}

struct socket_peer *alloc_jet_peer(const struct eventloop *loop, int fd)
{
	struct socket_peer *p = malloc(sizeof(*p));
	if (unlikely(p == NULL)) {
		return NULL;
	}
	if (init_socket_peer(loop, p, fd) < 0) {
		free(p);
		return NULL;
	} else {
		return p;
	}
}

static int copy_msg_to_write_buffer(struct socket_peer *p, const void *rendered,
			 uint32_t msg_len_be, size_t already_written)
{
	size_t to_write;
	uint32_t msg_len = jet_be32toh(msg_len_be);
	size_t free_space_in_buf = CONFIG_MAX_WRITE_BUFFER_SIZE - p->to_write;
	size_t bytes_to_copy =  (sizeof(msg_len_be) + msg_len) - already_written;

	if (unlikely(bytes_to_copy > free_space_in_buf)) {
		log_err("not enough space left in write buffer! %zu bytes of %i left", free_space_in_buf, CONFIG_MAX_WRITE_BUFFER_SIZE);
		return -1;
	}

	char *write_buffer_ptr = p->write_buffer + p->to_write;
	if (already_written < sizeof(msg_len_be)) {
		char *msg_len_ptr = (char *)(&msg_len_be);
		msg_len_ptr += already_written;
		to_write = sizeof(msg_len_be) - already_written;
		memcpy(write_buffer_ptr, msg_len_ptr, to_write);
		write_buffer_ptr += to_write;
		already_written += to_write;
		p->to_write += to_write;
	}

	size_t msg_offset = already_written - sizeof(msg_len_be);
	const char *message_ptr = (const char *)rendered + msg_offset;
	to_write = msg_len - msg_offset;
	memcpy(write_buffer_ptr, message_ptr, to_write);
	p->to_write += to_write;

	return 0;
}

int send_message(struct peer *p, const char *rendered, size_t len)
{
	struct socket_peer *s_peer = container_of(p, struct socket_peer, peer);
	int ret;
	struct iovec iov[3];
	ssize_t sent;
	size_t written = 0;
	uint32_t message_length = htonl(len);

	iov[0].iov_base = s_peer->write_buffer;
	iov[0].iov_len = s_peer->to_write;

	iov[1].iov_base = &message_length;
	iov[1].iov_len = sizeof(message_length);
/*
 * This pragma is used because iov_base is not declared const.
 * Nevertheless, I want to have the rendered parameter const. Therefore I
 * selectively disabled the cast-qual warning.
 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
	iov[2].iov_base = (void *)rendered;
#pragma GCC diagnostic pop
	iov[2].iov_len = len;

	sent = WRITEV(s_peer->ev.context.fd, iov, sizeof(iov) / sizeof(struct iovec));
	if (likely(sent == ((ssize_t)len + (ssize_t)sizeof(message_length)))) {
		return 0;
	}

	if (sent > 0) {
		written = (size_t)sent;
	}

	if (unlikely((sent == -1) &&
		((errno != EAGAIN) && (errno != EWOULDBLOCK)))) {
		log_err("unexpected %s error: %s!\n", "write",
			strerror(errno));
		return -1;
	}

	size_t already_written;
	if (written <= s_peer->to_write) {
		s_peer->to_write -= written;
		memmove(s_peer->write_buffer, s_peer->write_buffer + written, s_peer->to_write);
		already_written = 0;
	} else {
		already_written = written;
		s_peer->to_write = 0;
	}
	if (unlikely(copy_msg_to_write_buffer(s_peer, rendered, message_length,
		already_written) == -1)) {
		return -1;
	}

	if (sent == -1) {
		/* the write call has blocked */
		return 0;
	}

	/*
	 * The write call didn't block, but only wrote parts of the
	 * messages. Try to send the rest.
	 */
	ret = send_buffer(s_peer);
	return ret;
}
