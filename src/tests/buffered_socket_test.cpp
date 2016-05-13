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

static const int WRITEV_COMPLETE_WRITE = 1;
static char write_buffer[5000];

extern "C" {
	int fake_writev(int fd, const struct iovec *iov, int iovcnt)
	{
		if (fd == WRITEV_COMPLETE_WRITE) {
			size_t complete_length = 0;
			char *buf = write_buffer;
			for (int i = 0; i < iovcnt; i++) {
				memcpy(buf, iov[i].iov_base, iov[i].iov_len);
				complete_length += iov[i].iov_len;
				buf += iov[i].iov_len;
			}
			return complete_length;
		}
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

static enum callback_return eventloop_fake_failing_add(struct io_event *ev)
{
	(void)ev;
	return ABORT_LOOP;
}

struct F {
	F(int fd)
	{
		loop.create = NULL;
		loop.destroy = NULL;
		loop.run = NULL;
		loop.add = eventloop_fake_add;
		loop.remove = NULL;
		buffered_socket_init(&bs, fd, &loop, NULL, NULL);
	}

	~F()
	{
	}

	struct eventloop loop;
	struct buffered_socket bs;
};

BOOST_AUTO_TEST_CASE(test_buffered_socket_init_ok)
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

BOOST_AUTO_TEST_CASE(test_buffered_socket_init_fail)
{
	struct eventloop loop = {
		.create = NULL,
		.destroy = NULL,
		.run = NULL,
		.add = eventloop_fake_failing_add,
		.remove = NULL
	};
	
	struct buffered_socket bs;
	
	int ret = buffered_socket_init(&bs, -1, &loop, NULL, NULL);
	BOOST_CHECK(ret < 0);
}

BOOST_AUTO_TEST_CASE(test_buffered_socket_writev)
{
	F f(WRITEV_COMPLETE_WRITE);
	
	struct io_vector vec[2];
	vec[0].iov_base = "Hello";
	vec[0].iov_len = strlen((const char*)vec[0].iov_base);
	vec[1].iov_base = "World";
	vec[1].iov_len = strlen((const char *)vec[1].iov_base);
	int ret = buffered_socket_writev(&f.bs, vec, 2);
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(memcmp(write_buffer, "HelloWorld", strlen("HelloWorld")) == 0);
}
