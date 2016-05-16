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
#include <errno.h>
#include <sys/uio.h>

#include "buffered_socket.h"
#include "eventloop.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))
#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))

static const int WRITEV_COMPLETE_WRITE = 1;
static const int WRITEV_EINVAL = 2;
static const int WRITEV_PART_SEND_BLOCKS = 3;
static const int WRITEV_BLOCKS = 4;
static const int WRITEV_PART_SEND_SINGLE_BYTES = 5;
static const int WRITEV_PART_SEND_PARTS = 6;
static const int WRITEV_PART_SEND_FAILS = 7;
static const int WRITEV_PART_SEND_PARTS_EVENTLOOP_SEND_REST = 8;
static const int WRITEV_PART_SEND_PARTS_EVENTLOOP_SEND_FAILS = 9;

static const int READ_4 = 10;
static const int READ_5 = 11;
static const int READ_8 = 12;
static const int READ_FULL = 13;
static const int READ_CLOSE = 14;
static const int READ_ERROR = 15;
static const int READ_IN_CALLBACK = 16;

static char write_buffer[5000];
static char *write_buffer_ptr;

static size_t writev_parts_cnt;
static int send_parts_cnt;
static int send_parts_counter;
static bool called_from_eventloop;

static int read_called;
static char read_buffer[5000];

extern "C" {
	int fake_writev(int fd, const struct iovec *iov, int iovcnt)
	{
		switch (fd) {
		case WRITEV_COMPLETE_WRITE: {
			size_t complete_length = 0;
			for (int i = 0; i < iovcnt; i++) {
				memcpy(write_buffer_ptr, iov[i].iov_base, iov[i].iov_len);
				complete_length += iov[i].iov_len;
				write_buffer_ptr += iov[i].iov_len;
			}
			return complete_length;
		}

		case WRITEV_EINVAL:
		{
			errno = EINVAL;
			return -1;
		}

		case WRITEV_PART_SEND_PARTS_EVENTLOOP_SEND_FAILS:
		case WRITEV_PART_SEND_PARTS_EVENTLOOP_SEND_REST:
		case WRITEV_PART_SEND_FAILS:
		case WRITEV_PART_SEND_PARTS:
		case WRITEV_PART_SEND_SINGLE_BYTES:
		case WRITEV_PART_SEND_BLOCKS:
		{
			size_t complete_length = 0;
			size_t parts_cnt = writev_parts_cnt;
			for (int i = 0; i < iovcnt; i++) {
				int to_write = MIN(iov[i].iov_len, parts_cnt);
				memcpy(write_buffer_ptr, iov[i].iov_base, to_write);
				complete_length += to_write;
				write_buffer_ptr += to_write;
				parts_cnt -= to_write;
				if (parts_cnt == 0) {
					return complete_length;
				}
			}
			return complete_length;
		}

		case WRITEV_BLOCKS:
		{
			errno = EWOULDBLOCK;
			return -1;
		}
		default:
			return 0;
		}
	}

	int fake_send(int fd, void *buf, size_t count, int flags)
	{
		(void)flags;
		(void)buf;
		(void)count;

		switch (fd) {
		case WRITEV_PART_SEND_BLOCKS:
		{
			errno = EWOULDBLOCK;
			return -1;
		}

		case WRITEV_PART_SEND_SINGLE_BYTES:
		{
			*write_buffer_ptr = *((char *)buf);
			write_buffer_ptr++;
			return 1;
		}

		case WRITEV_PART_SEND_PARTS:
		{
			if (send_parts_counter < send_parts_cnt) {
				*write_buffer_ptr = *((char *)buf);
				write_buffer_ptr++;
				send_parts_counter++;
				return 1;
			} else {
				errno = EWOULDBLOCK;
				return -1;
			}
		}

		case WRITEV_PART_SEND_PARTS_EVENTLOOP_SEND_REST:
		{
			if (!called_from_eventloop) {
				if (send_parts_counter < send_parts_cnt) {
					*write_buffer_ptr = *((char *)buf);
					write_buffer_ptr++;
					send_parts_counter++;
					return 1;
				} else {
					errno = EWOULDBLOCK;
					return -1;
				}
			} else {
				*write_buffer_ptr = *((char *)buf);
				write_buffer_ptr++;
				return 1;
			}
		}

		case WRITEV_PART_SEND_PARTS_EVENTLOOP_SEND_FAILS:
		{
			if (!called_from_eventloop) {
				if (send_parts_counter < send_parts_cnt) {
					*write_buffer_ptr = *((char *)buf);
					write_buffer_ptr++;
					send_parts_counter++;
					return 1;
				} else {
					errno = EWOULDBLOCK;
					return -1;
				}
			} else {
				errno = EINVAL;
				return -1;
			}
		}

		case WRITEV_PART_SEND_FAILS:
		{
			errno = EINVAL;
			return -1;
		}

		default:
			return 0;
		}
	}

	int fake_read(int fd, void *buf, size_t count)
	{
		switch (fd) {
		case READ_4:
		{
			(void)count;
			if (read_called == 0) {
				read_called++;
				memcpy(buf, read_buffer, 4);
				return 4;
			} else {
				errno = EWOULDBLOCK;
				return -1;
			}
		}

		case READ_5:
		{
			(void)count;
			if (read_called == 0) {
				read_called++;
				memcpy(buf, read_buffer, 5);
				return 5;
			} else {
				errno = EWOULDBLOCK;
				return -1;
			}
		}

		case READ_8:
		{
			(void)count;
			if (read_called == 0) {
				read_called++;
				memcpy(buf, read_buffer, 8);
				return 8;
			} else {
				errno = EWOULDBLOCK;
				return -1;
			}
		}

		case READ_FULL:
		{
			if (read_called == 0) {
				read_called++;
				memset(buf, 'a', count);
				return count;
			} if (read_called == 1) {
				read_called++;
				memset(buf, 'b', count);
				return count;
			} else {
				errno = EWOULDBLOCK;
				return -1;
			}
		}

		case READ_IN_CALLBACK:
		{
			if (read_called == 0) {
				read_called++;
				memset(buf, 'a', 4);
				return 4;
			} if (read_called == 1) {
				read_called++;
				memset(buf, 'b', 2);
				return 2;
			} else {
				errno = EWOULDBLOCK;
				return -1;
			}
		}

		case READ_CLOSE:
		{
			return 0;
		}

		case READ_ERROR:
		{
			errno = EINVAL;
			return -1;
		}

		default:
			return -1;
		}
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

static void eventloop_fake_remove(struct io_event *ev)
{
	(void)ev;
}

struct F {
	F() : F(-1) {}
	F(int fd)
	{
		loop.create = NULL;
		loop.destroy = NULL;
		loop.run = NULL;
		loop.add = eventloop_fake_add;
		loop.remove = eventloop_fake_remove;
		buffered_socket_init(&bs, fd, &loop, error_func, this);
		write_buffer_ptr = write_buffer;
		send_parts_counter = 0;
		called_from_eventloop = false;
		read_called = 0;
		readcallback_called = 0;
		error_func_called = false;
	}

	static void error_func(void *context)
	{
		struct F *f = (struct F *)context;
		f->error_func_called = true;
	}

	static void read_callback(void *context, char *buf, ssize_t len)
	{
		struct F *f = (struct F *)context;
		memcpy(f->read_buffer, buf, len);
		f->read_len = len;
		f->readcallback_called++;
		if (f->bs.ev.context.fd == READ_IN_CALLBACK) {
			read_exactly(&f->bs, 2, read_callback, f);
		}
	}

	~F()
	{
	}

	int readcallback_called;
	bool error_func_called;
	struct eventloop loop;
	struct buffered_socket bs;

	char read_buffer[CONFIG_MAX_MESSAGE_SIZE];
	ssize_t read_len;
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
	static const char *send_buffer = "Morning has broken";
	static const size_t first_chunk_size = 8;

	F f(WRITEV_COMPLETE_WRITE);

	struct io_vector vec[2];
	vec[0].iov_base = send_buffer;
	vec[0].iov_len = first_chunk_size;
	vec[1].iov_base = send_buffer + first_chunk_size;
	vec[1].iov_len = strlen(send_buffer) - first_chunk_size;
	int ret = buffered_socket_writev(&f.bs, vec, ARRAY_SIZE(vec));
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(memcmp(write_buffer, send_buffer, strlen(send_buffer)) == 0);
}

BOOST_AUTO_TEST_CASE(test_buffered_socket_writev_inval)
{
	static const char *send_buffer = "foobar";
	static const size_t first_chunk_size = 2;

	F f(WRITEV_EINVAL);

	struct io_vector vec[2];
	vec[0].iov_base = send_buffer;
	vec[0].iov_len = first_chunk_size;
	vec[1].iov_base = send_buffer + first_chunk_size;
	vec[1].iov_len = strlen(send_buffer) - first_chunk_size;
	int ret = buffered_socket_writev(&f.bs, vec, ARRAY_SIZE(vec));
	BOOST_CHECK(ret < 0);
}

BOOST_AUTO_TEST_CASE(test_buffered_socket_writev_part_send_blocks)
{
	F f(WRITEV_PART_SEND_BLOCKS);

	writev_parts_cnt = 4;
	static const char *send_buffer = "HelloWorld";
	static const size_t first_chunk_size = 6;

	struct io_vector vec[2];
	vec[0].iov_base = send_buffer;
	vec[0].iov_len = first_chunk_size;
	vec[1].iov_base = send_buffer + first_chunk_size;
	vec[1].iov_len = strlen(send_buffer) - first_chunk_size;
	int ret = buffered_socket_writev(&f.bs, vec, ARRAY_SIZE(vec));
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(memcmp(write_buffer, send_buffer, writev_parts_cnt) == 0);
	BOOST_CHECK(memcmp(f.bs.write_buffer, send_buffer + writev_parts_cnt, strlen(send_buffer) - writev_parts_cnt) == 0);
}

BOOST_AUTO_TEST_CASE(test_buffered_socket_writev_part_send_blocks_first_chunk_smaller_than_part)
{
	F f(WRITEV_PART_SEND_BLOCKS);

	writev_parts_cnt = 8;
	static const char *send_buffer = "I want to break free";
	static const size_t first_chunk_size = 4;

	struct io_vector vec[2];
	vec[0].iov_base = send_buffer;
	vec[0].iov_len = first_chunk_size;
	vec[1].iov_base = send_buffer + first_chunk_size;
	vec[1].iov_len = strlen(send_buffer) - first_chunk_size;
	int ret = buffered_socket_writev(&f.bs, vec, ARRAY_SIZE(vec));
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(memcmp(write_buffer, send_buffer, writev_parts_cnt) == 0);
	BOOST_CHECK(memcmp(f.bs.write_buffer, send_buffer + writev_parts_cnt, strlen(send_buffer) - writev_parts_cnt) == 0);
}

BOOST_AUTO_TEST_CASE(test_buffered_socket_writev_blocks)
{
	static const char *send_buffer = "In the ghetto";
	static const size_t first_chunk_size = 7;

	F f(WRITEV_BLOCKS);

	struct io_vector vec[2];
	vec[0].iov_base = send_buffer;
	vec[0].iov_len = first_chunk_size;
	vec[1].iov_base = send_buffer + first_chunk_size;
	vec[1].iov_len = strlen(send_buffer) - first_chunk_size;
	int ret = buffered_socket_writev(&f.bs, vec, ARRAY_SIZE(vec));
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(memcmp(f.bs.write_buffer, send_buffer, strlen(send_buffer)) == 0);
}

BOOST_AUTO_TEST_CASE(test_buffered_socket_writev_blocks_buffer_too_small)
{
	char buffer[CONFIG_MAX_WRITE_BUFFER_SIZE + 1];

	F f(WRITEV_BLOCKS);

	struct io_vector vec[1];
	vec[0].iov_base = buffer;
	vec[0].iov_len = sizeof(buffer);
	int ret = buffered_socket_writev(&f.bs, vec, ARRAY_SIZE(vec));
	BOOST_CHECK(ret < 0);
}

BOOST_AUTO_TEST_CASE(test_buffered_socket_writev_blocks_buffer_fits)
{
	char buffer[CONFIG_MAX_WRITE_BUFFER_SIZE] = {0};

	F f(WRITEV_BLOCKS);

	struct io_vector vec[1];
	vec[0].iov_base = buffer;
	vec[0].iov_len = sizeof(buffer);
	int ret = buffered_socket_writev(&f.bs, vec, ARRAY_SIZE(vec));
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(::memcmp(f.bs.write_buffer, buffer, sizeof(buffer)) == 0);
}

BOOST_AUTO_TEST_CASE(test_buffered_socket_writev_parts_send_single)
{
	static const char *send_buffer = "I want to ride my bicycle";
	static const size_t first_chunk_size = 9;
	writev_parts_cnt = 7;

	F f(WRITEV_PART_SEND_SINGLE_BYTES);

	struct io_vector vec[2];
	vec[0].iov_base = send_buffer;
	vec[0].iov_len = first_chunk_size;
	vec[1].iov_base = send_buffer + first_chunk_size;
	vec[1].iov_len = strlen(send_buffer) - first_chunk_size;
	int ret = buffered_socket_writev(&f.bs, vec, ARRAY_SIZE(vec));
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(::memcmp(write_buffer, send_buffer, strlen(send_buffer)) == 0);
}

BOOST_AUTO_TEST_CASE(test_buffered_socket_writev_parts_send_parts)
{
	static const char *send_buffer = "We are the champions";
	static const size_t first_chunk_size = 3;
	writev_parts_cnt = 1;
	send_parts_cnt = 5;

	F f(WRITEV_PART_SEND_PARTS);

	struct io_vector vec[2];
	vec[0].iov_base = send_buffer;
	vec[0].iov_len = first_chunk_size;
	vec[1].iov_base = send_buffer + first_chunk_size;
	vec[1].iov_len = strlen(send_buffer) - first_chunk_size;
	int ret = buffered_socket_writev(&f.bs, vec, ARRAY_SIZE(vec));
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(::memcmp(write_buffer, send_buffer, writev_parts_cnt + send_parts_cnt) == 0);
	BOOST_CHECK(::memcmp(f.bs.write_buffer, send_buffer + writev_parts_cnt + send_parts_cnt, strlen(send_buffer) - writev_parts_cnt - send_parts_cnt) == 0);
}

BOOST_AUTO_TEST_CASE(test_buffered_socket_writev_parts_send_fails)
{
	static const char *send_buffer = "The show must go on";
	static const size_t first_chunk_size = 3;
	writev_parts_cnt = 1;
	send_parts_cnt = 5;

	F f(WRITEV_PART_SEND_FAILS);

	struct io_vector vec[2];
	vec[0].iov_base = send_buffer;
	vec[0].iov_len = first_chunk_size;
	vec[1].iov_base = send_buffer + first_chunk_size;
	vec[1].iov_len = strlen(send_buffer) - first_chunk_size;
	int ret = buffered_socket_writev(&f.bs, vec, ARRAY_SIZE(vec));
	BOOST_CHECK(ret < 0);
}

BOOST_AUTO_TEST_CASE(test_buffered_socket_writev_parts_send_parts_eventloop_send_rest)
{
	static const char *send_buffer = "Another one bites the dust";
	static const size_t first_chunk_size = 5;
	writev_parts_cnt = 2;
	send_parts_cnt = 4;

	F f(WRITEV_PART_SEND_PARTS_EVENTLOOP_SEND_REST);

	struct io_vector vec[2];
	vec[0].iov_base = send_buffer;
	vec[0].iov_len = first_chunk_size;
	vec[1].iov_base = send_buffer + first_chunk_size;
	vec[1].iov_len = strlen(send_buffer) - first_chunk_size;
	int ret = buffered_socket_writev(&f.bs, vec, ARRAY_SIZE(vec));
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(::memcmp(write_buffer, send_buffer, writev_parts_cnt + send_parts_cnt) == 0);
	BOOST_CHECK(::memcmp(f.bs.write_buffer, send_buffer + writev_parts_cnt + send_parts_cnt, strlen(send_buffer) - writev_parts_cnt - send_parts_cnt) == 0);

	called_from_eventloop = true;
	enum callback_return cb_ret = f.bs.ev.write_function(&f.bs.ev.context);
	BOOST_CHECK(cb_ret == CONTINUE_LOOP);
	BOOST_CHECK(::memcmp(write_buffer, send_buffer, strlen(send_buffer)) == 0);
}

BOOST_AUTO_TEST_CASE(test_buffered_socket_writev_parts_send_parts_eventloop_send_fail)
{
	static const char *send_buffer = "Don't stop me now";
	static const size_t first_chunk_size = 2;
	writev_parts_cnt = 2;
	send_parts_cnt = 4;

	F f(WRITEV_PART_SEND_PARTS_EVENTLOOP_SEND_FAILS);

	struct io_vector vec[2];
	vec[0].iov_base = send_buffer;
	vec[0].iov_len = first_chunk_size;
	vec[1].iov_base = send_buffer + first_chunk_size;
	vec[1].iov_len = strlen(send_buffer) - first_chunk_size;
	int ret = buffered_socket_writev(&f.bs, vec, ARRAY_SIZE(vec));
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(::memcmp(write_buffer, send_buffer, writev_parts_cnt + send_parts_cnt) == 0);
	BOOST_CHECK(::memcmp(f.bs.write_buffer, send_buffer + writev_parts_cnt + send_parts_cnt, strlen(send_buffer) - writev_parts_cnt - send_parts_cnt) == 0);

	called_from_eventloop = true;
	enum callback_return cb_ret = f.bs.ev.write_function(&f.bs.ev.context);
	BOOST_CHECK(cb_ret == CONTINUE_LOOP);
	BOOST_CHECK(f.error_func_called);
}

BOOST_AUTO_TEST_CASE(test_read_exactly)
{
	static const char *test_string = "aaaa";
	::memcpy(read_buffer, test_string, ::strlen(test_string));
	F f(READ_4);

	int ret = read_exactly(&f.bs, 4, f.read_callback, &f);
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(f.readcallback_called == 1);
	BOOST_CHECK(f.read_len = 4);
	BOOST_CHECK(memcmp(f.read_buffer, test_string, f.read_len) == 0);
	BOOST_CHECK(f.bs.write_ptr - f.bs.read_ptr == 0);
}

BOOST_AUTO_TEST_CASE(test_read_exactly_some_more)
{
	static const char *test_string = "aaaaa";
	::memcpy(read_buffer, test_string, ::strlen(test_string));
	F f(READ_5);

	int ret = read_exactly(&f.bs, 4, f.read_callback, &f);
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(f.readcallback_called == 1);
	BOOST_CHECK(f.read_len = 4);
	BOOST_CHECK(memcmp(f.read_buffer, test_string, f.read_len) == 0);
	BOOST_CHECK(f.bs.write_ptr - f.bs.read_ptr == 1);
}

BOOST_AUTO_TEST_CASE(test_read_exactly_called_twice)
{
	static const char *test_string = "aaaabbbb";
	::memcpy(read_buffer, test_string, ::strlen(test_string));
	F f(READ_8);

	int ret = read_exactly(&f.bs, 4, f.read_callback, &f);
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(f.readcallback_called == 2);
	BOOST_CHECK(f.read_len = 4);
	BOOST_CHECK(memcmp(f.read_buffer, test_string + 4, f.read_len) == 0);
	BOOST_CHECK(f.bs.write_ptr - f.bs.read_ptr == 0);
}

BOOST_AUTO_TEST_CASE(test_read_exactly_nearly_complete_buffer)
{
	F f(READ_FULL);
	size_t read_size = CONFIG_MAX_MESSAGE_SIZE - 1;
	int ret = read_exactly(&f.bs, read_size, f.read_callback, &f);
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(f.readcallback_called == 2);
	BOOST_CHECK(f.read_len = read_size);
	BOOST_CHECK(f.bs.write_ptr - f.bs.read_ptr == 1);
	BOOST_CHECK(f.read_buffer[0] == 'a');
	for (unsigned int i = 1; i < read_size; i++) {
		BOOST_CHECK(f.read_buffer[i] == 'b');
	}
}

BOOST_AUTO_TEST_CASE(test_read_exactly_complete_buffer)
{
	F f(READ_FULL);
	size_t read_size = CONFIG_MAX_MESSAGE_SIZE;
	int ret = read_exactly(&f.bs, read_size, f.read_callback, &f);
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(f.readcallback_called == 2);
	BOOST_CHECK(f.read_len = read_size);
	BOOST_CHECK(f.bs.write_ptr - f.bs.read_ptr == 0);
	for (unsigned int i = 0; i < read_size; i++) {
		BOOST_CHECK(f.read_buffer[i] == 'b');
	}
}

BOOST_AUTO_TEST_CASE(test_read_exactly_more_than_buffer)
{
	F f(READ_FULL);
	size_t read_size = CONFIG_MAX_MESSAGE_SIZE + 1;
	int ret = read_exactly(&f.bs, read_size, f.read_callback, &f);
	BOOST_CHECK(ret == IO_TOOMUCHDATA);
}

BOOST_AUTO_TEST_CASE(test_read_exactly_read_close)
{
	F f(READ_CLOSE);
	size_t read_size = 4;
	int ret = read_exactly(&f.bs, read_size, f.read_callback, &f);
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(f.readcallback_called == 1);
	BOOST_CHECK(f.read_len == 0);
}

BOOST_AUTO_TEST_CASE(test_read_exactly_read_error)
{
	F f(READ_ERROR);
	size_t read_size = 4;
	int ret = read_exactly(&f.bs, read_size, f.read_callback, &f);
	BOOST_CHECK(ret == IO_ERROR);
	BOOST_CHECK(f.readcallback_called == 0);
}

BOOST_AUTO_TEST_CASE(test_read_exactly_read_in_callback)
{
	F f(READ_IN_CALLBACK);
	size_t read_size = 4;
	int ret = read_exactly(&f.bs, read_size, f.read_callback, &f);
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(f.readcallback_called == 2);
}