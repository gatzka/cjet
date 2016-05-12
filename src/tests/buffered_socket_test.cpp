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

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MAIN
#define BOOST_TEST_MODULE buffered_socket_tests

#include <boost/test/unit_test.hpp>
#include <sys/uio.h>

#include "buffered_socket.h"
#include "eventloop.h"

extern "C" {
	int fake_writev(int fd, const struct iovec *iov, int iovcnt)
	{
		(void)fd;
		(void)iov;
		(void)iovcnt;
		return 0;
	}
	
	int fake_send(int fd, void *buf, size_t count, int flags)
	{
		(void)flags;
		(void)fd;
		(void)buf;
		(void)count;
		return 0;
	}
	
	int fake_read(int fd, void *buf, size_t count)
	{
		(void)fd;
		(void)buf;
		(void)count;
		return 0;
	}
}

static enum callback_return eventloop_fake_add(struct io_event *ev)
{
	(void)ev;
	return CONTINUE_LOOP;
}

BOOST_AUTO_TEST_CASE(init_buffered_socket_ok)
{
	struct eventloop loop = {
		.create = NULL,
		.destroy = NULL,
		.run = NULL,
		.add = eventloop_fake_add,
		.remove = NULL
	};
	
	struct buffered_socket bs;
	
	int ret = buffered_socket_init(&bs, -1, &loop, NULL, NULL);
	BOOST_CHECK(ret == 0);
}
