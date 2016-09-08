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

#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>

#include "buffered_socket.h"
#include "compiler.h"
#include "socket.h"

ssize_t socket_read(socket_type sock, void *buf, size_t count)
{
	return read(sock, buf, count);
}

ssize_t socket_writev(socket_type sock, struct buffered_socket_io_vector *io_vec, unsigned int count)
{
	struct iovec iov[count];

	if (unlikely(count == 0)) {
		return 0;
	}

/*
 * This pragma is used because iov_base is not declared const.
 * Nevertheless, I want to have the parameter io_vec const. Therefore I
 * selectively disabled the cast-qual warning.
 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
	for (unsigned int i = 0; i < count; i++) {
		iov[i].iov_base = (void *)io_vec[i].iov_base;
		iov[i].iov_len = io_vec[i].iov_len;
	}
#pragma GCC diagnostic pop
	return writev(sock, iov, sizeof(iov) / sizeof(struct iovec));
}

int socket_close(socket_type sock)
{
	return close(sock);
}
