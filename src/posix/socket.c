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

#include <sys/uio.h>
#include <unistd.h>

#include "compiler.h"
#include "socket.h"

cjet_ssize_t socket_read(socket_type sock, void *buf, size_t count)
{
	return read(sock, buf, count);
}

cjet_ssize_t socket_writev_with_prefix(socket_type sock, void *buf, size_t len, struct socket_io_vector *io_vec, unsigned int count)
{
	struct iovec iov[count + 1];

	if (unlikely((len == 0) && (count == 0))) {
		return 0;
	}

	iov[0].iov_base = buf;
	iov[0].iov_len = len;
/*
 * This pragma is used because iov_base is not declared const.
 * Nevertheless, I want to have the parameter io_vec const. Therefore I
 * selectively disabled the cast-qual warning.
 */
_Pragma ("GCC diagnostic ignored \"-Wcast-qual\"")
	for (unsigned int i = 0; i < count; i++) {
		iov[i + 1].iov_base = (void *)io_vec[i].iov_base;
		iov[i + 1].iov_len = io_vec[i].iov_len;
	}
_Pragma ("GCC diagnostic error \"-Wcast-qual\"")
	return writev(sock, iov, sizeof(iov) / sizeof(struct iovec));
}

int socket_close(socket_type sock)
{
	return close(sock);
}
