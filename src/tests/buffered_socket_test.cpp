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
#include "compiler.h"
#include "eventloop.h"
#include "generated/os_config.h"

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

static const int READ_COMPLETE_BUFFER = 10;
static const int READ_FULL = 11;
static const int READ_CLOSE = 12;
static const int READ_ERROR = 13;
static const int READ_EXACTLY_IN_CALLBACK = 14;
static const int READ_FAILING_EV_ADD = 15;
static const int READ_FROM_EVENTLOOP = 16;
static const int READ_FROM_EVENTLOOP_FAIL = 17;
static const int READ_UNTIL_IN_CALLBACK = 18;
static const int READ_CLOSE_FROM_EVENTLOOP = 19;

static char write_buffer[5000];
static char *write_buffer_ptr;

static size_t writev_parts_cnt;
static int send_parts_cnt;
static int send_parts_counter;
static bool called_from_eventloop;
static bool first_writev;

static int read_called;
static const char *readbuffer;
static const char *readbuffer_ptr;
static size_t readbuffer_length;

static unsigned int MAGIC = 0x1234;

extern "C" {

	static cjet_ssize_t write_away(void *buf, size_t len, struct socket_io_vector *io_vec, unsigned int count, size_t parts_cnt)
	{
		size_t complete_length = 0;
		int will_write = MIN(len, parts_cnt);
		memcpy(write_buffer_ptr, buf, will_write);
		complete_length += will_write;
		write_buffer_ptr += will_write;
		parts_cnt -= will_write;
		if (parts_cnt == 0) {
			return complete_length;
		}

		for (unsigned int i = 0; i < count; i++) {
			will_write = MIN(io_vec[i].iov_len, parts_cnt);
			memcpy(write_buffer_ptr, io_vec[i].iov_base, will_write);
			complete_length += will_write;
			write_buffer_ptr += will_write;
			parts_cnt -= will_write;
			if (parts_cnt == 0) {
				return complete_length;
			}
		}
		return complete_length;
	}

	cjet_ssize_t socket_writev_with_prefix(socket_type sock, void *buf, size_t len, struct socket_io_vector *io_vec, unsigned int count)
	{
		switch (sock) {
		case WRITEV_COMPLETE_WRITE: {
			return write_away(buf, len, io_vec, count, SIZE_MAX);
		}

		case WRITEV_EINVAL:
		{
			errno = EINVAL;
			return -1;
		}

		case WRITEV_PART_SEND_SINGLE_BYTES:
		case WRITEV_PART_SEND_BLOCKS:
		{
			return write_away(buf, len, io_vec, count, writev_parts_cnt);
		}

		case WRITEV_PART_SEND_PARTS_EVENTLOOP_SEND_FAILS:
		{
			size_t parts_cnt;
			if (first_writev) {
				parts_cnt = writev_parts_cnt;
				first_writev = false;
			} else {
				if (!called_from_eventloop) {
					if (send_parts_counter < send_parts_cnt) {
						parts_cnt = 1;
						send_parts_counter++;
					} else {
						errno = EWOULDBLOCK;
						return -1;
					}
				} else {
					errno = EINVAL;
					return -1;
				}
			}

			return write_away(buf, len, io_vec, count, parts_cnt);
		}

		case WRITEV_PART_SEND_PARTS_EVENTLOOP_SEND_REST:
		{
			size_t parts_cnt;
			if (first_writev) {
				parts_cnt = writev_parts_cnt;
				first_writev = false;
			} else {
				if (!called_from_eventloop) {
					if (send_parts_counter < send_parts_cnt) {
						parts_cnt = 1;
						send_parts_counter++;
					} else {
						errno = EWOULDBLOCK;
						return -1;
					}
				} else {
					parts_cnt = 1;
				}
			}

			return write_away(buf, len, io_vec, count, parts_cnt);
		}

		case WRITEV_PART_SEND_FAILS:
		{
			if (first_writev) {
				first_writev = false;
				return write_away(buf, len, io_vec, count, writev_parts_cnt);
			} else {
				errno = EINVAL;
				return -1;
			}
		}

		case WRITEV_PART_SEND_PARTS:
		{
			size_t parts_cnt;
			if (first_writev) {
				parts_cnt = writev_parts_cnt;
				first_writev = false;
			} else {
				if (send_parts_counter < send_parts_cnt) {
					parts_cnt = 1;
					send_parts_counter++;
				} else {
					errno = EWOULDBLOCK;
					return -1;
				}
			}

			return write_away(buf, len, io_vec, count, parts_cnt);
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

	cjet_ssize_t socket_read(socket_type sock, void *buf, size_t count)
	{
		switch (sock) {
		case READ_UNTIL_IN_CALLBACK:
		case READ_COMPLETE_BUFFER:
		{
			if (readbuffer_length > 0) {
				size_t len = MIN(readbuffer_length, count);
				memcpy(buf, readbuffer_ptr, len);
				readbuffer_length -= len;
				readbuffer_ptr += len;
				return len;
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
			} else if (read_called == 1) {
				read_called++;
				memset(buf, 'b', count);
				return count;
			} else {
				errno = EWOULDBLOCK;
				return -1;
			}
		}

		case READ_EXACTLY_IN_CALLBACK:
		{
			if (read_called == 0) {
				read_called++;
				memset(buf, 'a', 4);
				return 4;
			} else if (read_called == 1) {
				read_called++;
				memset(buf, 'b', 2);
				return 2;
			} else {
				errno = EWOULDBLOCK;
				return -1;
			}
		}

		case READ_FROM_EVENTLOOP:
		{
			if (read_called == 0) {
				read_called++;
				errno = EWOULDBLOCK;
				return -1;
			} else  {
				if (readbuffer_length > 0) {
					size_t len = MIN(readbuffer_length, count);
					readbuffer_length -= len;
					memcpy(buf, readbuffer, len);
					return len;
				} else {
					errno = EWOULDBLOCK;
					return -1;
				}
			}
		}
			
		case READ_CLOSE_FROM_EVENTLOOP:
		{
			if (read_called == 0) {
				read_called++;
				errno = EWOULDBLOCK;
				return -1;
			} else  {
				return 0;
			}
		}

		case READ_FROM_EVENTLOOP_FAIL:
		{
			if (read_called == 0) {
				read_called++;
				errno = EWOULDBLOCK;
				return -1;
			} else if (read_called == 1) {
				read_called++;
				errno = EINVAL;
				return -1;
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
	
	int socket_close(socket_type sock)
	{
		(void)sock;
		return 0;
	}
}

static enum eventloop_return eventloop_fake_add(const void *this_ptr, const struct io_event *ev)
{
	BOOST_REQUIRE_MESSAGE(this_ptr == &MAGIC, "this_ptr does not point to the eventloop!");
	(void)ev;
	return EL_CONTINUE_LOOP;
}

static enum eventloop_return eventloop_fake_failing_add(const void *this_ptr, const struct io_event *ev)
{
	BOOST_REQUIRE_MESSAGE(this_ptr == &MAGIC, "this_ptr does not point to the eventloop!");
	(void)ev;
	return EL_ABORT_LOOP;
}

static void eventloop_fake_remove(const void *this_ptr, const struct io_event *ev)
{
	BOOST_REQUIRE_MESSAGE(this_ptr == &MAGIC, "this_ptr does not point to the eventloop!");
	(void)ev;
}

struct F {
	F(int fd)
	{
		loop.init = NULL;
		loop.destroy = NULL;
		loop.run = NULL;
		if (fd == READ_FAILING_EV_ADD) {
			loop.add = eventloop_fake_failing_add;
		} else {
			loop.add = eventloop_fake_add;
		}
		loop.remove = eventloop_fake_remove;
		loop.this_ptr = &MAGIC;
		bs = buffered_socket_acquire();
		buffered_socket_init(bs, fd, &loop, error_func, this);
		bs->write_buffer_ptr = NULL;
		bs->read_callback = NULL;
		bs->read_callback_context = NULL;
		write_buffer_ptr = write_buffer;
		send_parts_counter = 0;
		called_from_eventloop = false;
		readbuffer_ptr = readbuffer;
		first_writev = true;
		read_called = 0;
		read_len = 0;
		readcallback_called = 0;
		error_func_called = false;
		error_func_alt_called = false;
	}

	static void error_func(void *context)
	{
		struct F *f = (struct F *)context;
		f->error_func_called = true;
	}

	static void error_func_alt(void *context)
	{
		struct F *f = (struct F *)context;
		f->error_func_alt_called = true;
	}

	static enum bs_read_callback_return read_callback(void *context, uint8_t *buf, size_t len)
	{
		struct F *f = (struct F *)context;
		memcpy(f->read_buffer, buf, len);
		f->read_len = len;
		f->readcallback_called++;
		if (f->bs->ev.sock == READ_EXACTLY_IN_CALLBACK) {
			buffered_socket_read_exactly(f->bs, 2, read_callback, f);
		} else if (f->bs->ev.sock == READ_UNTIL_IN_CALLBACK) {
			buffered_socket_read_until(f->bs, "\n\r", read_callback, f);
		}
		return BS_OK;
	}

	~F()
	{
		if (bs != NULL) {
			buffered_socket_release(bs);
		}
	}

	size_t readcallback_called;
	bool error_func_called;
	bool error_func_alt_called;
	struct eventloop loop;
	struct buffered_socket *bs;

	char read_buffer[CONFIG_MAX_MESSAGE_SIZE];
	size_t read_len;
};

BOOST_AUTO_TEST_CASE(test_buffered_socket_writev)
{
	static const char *send_buffer = "Morning has broken";
	static const size_t first_chunk_size = 8;

	F f(WRITEV_COMPLETE_WRITE);

	struct socket_io_vector vec[2];
	vec[0].iov_base = send_buffer;
	vec[0].iov_len = first_chunk_size;
	vec[1].iov_base = send_buffer + first_chunk_size;
	vec[1].iov_len = strlen(send_buffer) - first_chunk_size;
	int ret = buffered_socket_writev(f.bs, vec, ARRAY_SIZE(vec));
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(memcmp(write_buffer, send_buffer, strlen(send_buffer)) == 0);
}

BOOST_AUTO_TEST_CASE(test_buffered_socket_writev_inval)
{
	static const char *send_buffer = "foobar";
	static const size_t first_chunk_size = 2;

	F f(WRITEV_EINVAL);

	struct socket_io_vector vec[2];
	vec[0].iov_base = send_buffer;
	vec[0].iov_len = first_chunk_size;
	vec[1].iov_base = send_buffer + first_chunk_size;
	vec[1].iov_len = strlen(send_buffer) - first_chunk_size;
	int ret = buffered_socket_writev(f.bs, vec, ARRAY_SIZE(vec));
	BOOST_CHECK(ret < 0);
}

BOOST_AUTO_TEST_CASE(test_buffered_socket_writev_part_send_blocks)
{
	F f(WRITEV_PART_SEND_BLOCKS);

	writev_parts_cnt = 4;
	static const char *send_buffer = "HelloWorld";
	static const size_t first_chunk_size = 6;

	struct socket_io_vector vec[2];
	vec[0].iov_base = send_buffer;
	vec[0].iov_len = first_chunk_size;
	vec[1].iov_base = send_buffer + first_chunk_size;
	vec[1].iov_len = strlen(send_buffer) - first_chunk_size;
	int ret = buffered_socket_writev(f.bs, vec, ARRAY_SIZE(vec));
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(memcmp(write_buffer, send_buffer, writev_parts_cnt) == 0);
	BOOST_CHECK(memcmp(f.bs->write_buffer, send_buffer + writev_parts_cnt, strlen(send_buffer) - writev_parts_cnt) == 0);
}

BOOST_AUTO_TEST_CASE(test_buffered_socket_writev_part_send_blocks_first_chunk_smaller_than_part)
{
	F f(WRITEV_PART_SEND_BLOCKS);

	writev_parts_cnt = 8;
	static const char *send_buffer = "I want to break free";
	static const size_t first_chunk_size = 4;

	struct socket_io_vector vec[2];
	vec[0].iov_base = send_buffer;
	vec[0].iov_len = first_chunk_size;
	vec[1].iov_base = send_buffer + first_chunk_size;
	vec[1].iov_len = strlen(send_buffer) - first_chunk_size;
	int ret = buffered_socket_writev(f.bs, vec, ARRAY_SIZE(vec));
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(memcmp(write_buffer, send_buffer, writev_parts_cnt) == 0);
	BOOST_CHECK(memcmp(f.bs->write_buffer, send_buffer + writev_parts_cnt, strlen(send_buffer) - writev_parts_cnt) == 0);
}

BOOST_AUTO_TEST_CASE(test_buffered_socket_writev_blocks)
{
	static const char *send_buffer = "In the ghetto";
	static const size_t first_chunk_size = 7;

	F f(WRITEV_BLOCKS);

	struct socket_io_vector vec[2];
	vec[0].iov_base = send_buffer;
	vec[0].iov_len = first_chunk_size;
	vec[1].iov_base = send_buffer + first_chunk_size;
	vec[1].iov_len = strlen(send_buffer) - first_chunk_size;
	int ret = buffered_socket_writev(f.bs, vec, ARRAY_SIZE(vec));
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(memcmp(f.bs->write_buffer, send_buffer, strlen(send_buffer)) == 0);
}

BOOST_AUTO_TEST_CASE(test_buffered_socket_writev_blocks_buffer_too_small)
{
	char buffer[CONFIG_MAX_WRITE_BUFFER_SIZE + 1];

	F f(WRITEV_BLOCKS);

	struct socket_io_vector vec[1];
	vec[0].iov_base = buffer;
	vec[0].iov_len = sizeof(buffer);
	int ret = buffered_socket_writev(f.bs, vec, ARRAY_SIZE(vec));
	BOOST_CHECK(ret < 0);
}

BOOST_AUTO_TEST_CASE(test_buffered_socket_writev_blocks_buffer_fits)
{
	char buffer[CONFIG_MAX_WRITE_BUFFER_SIZE] = {0};

	F f(WRITEV_BLOCKS);

	struct socket_io_vector vec[1];
	vec[0].iov_base = buffer;
	vec[0].iov_len = sizeof(buffer);
	int ret = buffered_socket_writev(f.bs, vec, ARRAY_SIZE(vec));
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(::memcmp(f.bs->write_buffer, buffer, sizeof(buffer)) == 0);
}

BOOST_AUTO_TEST_CASE(test_buffered_socket_writev_parts_send_single)
{
	static const char *send_buffer = "I want to ride my bicycle";
	static const size_t first_chunk_size = 9;
	writev_parts_cnt = 7;

	F f(WRITEV_PART_SEND_SINGLE_BYTES);

	struct socket_io_vector vec[2];
	vec[0].iov_base = send_buffer;
	vec[0].iov_len = first_chunk_size;
	vec[1].iov_base = send_buffer + first_chunk_size;
	vec[1].iov_len = strlen(send_buffer) - first_chunk_size;
	int ret = buffered_socket_writev(f.bs, vec, ARRAY_SIZE(vec));
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

	struct socket_io_vector vec[2];
	vec[0].iov_base = send_buffer;
	vec[0].iov_len = first_chunk_size;
	vec[1].iov_base = send_buffer + first_chunk_size;
	vec[1].iov_len = strlen(send_buffer) - first_chunk_size;
	int ret = buffered_socket_writev(f.bs, vec, ARRAY_SIZE(vec));
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(::memcmp(write_buffer, send_buffer, writev_parts_cnt + send_parts_cnt) == 0);
	BOOST_CHECK(::memcmp(f.bs->write_buffer, send_buffer + writev_parts_cnt + send_parts_cnt, strlen(send_buffer) - writev_parts_cnt - send_parts_cnt) == 0);
}

BOOST_AUTO_TEST_CASE(test_buffered_socket_writev_parts_send_fails)
{
	static const char *send_buffer = "The show must go on";
	static const size_t first_chunk_size = 3;
	writev_parts_cnt = 1;
	send_parts_cnt = 5;

	F f(WRITEV_PART_SEND_FAILS);

	struct socket_io_vector vec[2];
	vec[0].iov_base = send_buffer;
	vec[0].iov_len = first_chunk_size;
	vec[1].iov_base = send_buffer + first_chunk_size;
	vec[1].iov_len = strlen(send_buffer) - first_chunk_size;
	int ret = buffered_socket_writev(f.bs, vec, ARRAY_SIZE(vec));
	BOOST_CHECK(ret < 0);
}

BOOST_AUTO_TEST_CASE(test_buffered_socket_writev_parts_send_parts_eventloop_send_rest)
{
	static const char *send_buffer = "Another one bites the dust";
	static const size_t first_chunk_size = 5;
	writev_parts_cnt = 2;
	send_parts_cnt = 4;

	F f(WRITEV_PART_SEND_PARTS_EVENTLOOP_SEND_REST);

	struct socket_io_vector vec[2];
	vec[0].iov_base = send_buffer;
	vec[0].iov_len = first_chunk_size;
	vec[1].iov_base = send_buffer + first_chunk_size;
	vec[1].iov_len = strlen(send_buffer) - first_chunk_size;
	int ret = buffered_socket_writev(f.bs, vec, ARRAY_SIZE(vec));
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(::memcmp(write_buffer, send_buffer, writev_parts_cnt + send_parts_cnt) == 0);
	BOOST_CHECK(::memcmp(f.bs->write_buffer, send_buffer + writev_parts_cnt + send_parts_cnt, strlen(send_buffer) - writev_parts_cnt - send_parts_cnt) == 0);

	called_from_eventloop = true;
	enum eventloop_return cb_ret = f.bs->ev.write_function(&f.bs->ev);
	BOOST_CHECK(cb_ret == EL_CONTINUE_LOOP);
	BOOST_CHECK(::memcmp(write_buffer, send_buffer, strlen(send_buffer)) == 0);
}

BOOST_AUTO_TEST_CASE(test_buffered_socket_writev_parts_send_parts_eventloop_send_fail)
{
	static const char *send_buffer = "Don't stop me now";
	static const size_t first_chunk_size = 2;
	writev_parts_cnt = 2;
	send_parts_cnt = 4;

	F f(WRITEV_PART_SEND_PARTS_EVENTLOOP_SEND_FAILS);

	struct socket_io_vector vec[2];
	vec[0].iov_base = send_buffer;
	vec[0].iov_len = first_chunk_size;
	vec[1].iov_base = send_buffer + first_chunk_size;
	vec[1].iov_len = strlen(send_buffer) - first_chunk_size;
	int ret = buffered_socket_writev(f.bs, vec, ARRAY_SIZE(vec));
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(::memcmp(write_buffer, send_buffer, writev_parts_cnt + send_parts_cnt) == 0);
	BOOST_CHECK(::memcmp(f.bs->write_buffer, send_buffer + writev_parts_cnt + send_parts_cnt, strlen(send_buffer) - writev_parts_cnt - send_parts_cnt) == 0);

	called_from_eventloop = true;
	enum eventloop_return cb_ret = f.bs->ev.write_function(&f.bs->ev);
	BOOST_CHECK(cb_ret == EL_CONTINUE_LOOP);
	BOOST_CHECK(f.error_func_called);
}

BOOST_AUTO_TEST_CASE(test_read_exactly)
{
	readbuffer = "aaaa";
	readbuffer_length = ::strlen(readbuffer);
	F f(READ_COMPLETE_BUFFER);

	int ret = buffered_socket_read_exactly(f.bs, 4, f.read_callback, &f);
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(f.readcallback_called == 1);
	BOOST_CHECK(f.read_len = 4);
	BOOST_CHECK(memcmp(f.read_buffer, readbuffer, f.read_len) == 0);
	BOOST_CHECK(f.bs->write_ptr - f.bs->read_ptr == 0);
}

BOOST_AUTO_TEST_CASE(test_read_exactly_some_more)
{
	readbuffer = "aaaaa";
	readbuffer_length = ::strlen(readbuffer);
	F f(READ_COMPLETE_BUFFER);

	int ret = buffered_socket_read_exactly(f.bs, 4, f.read_callback, &f);
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(f.readcallback_called == 1);
	BOOST_CHECK(f.read_len = 4);
	BOOST_CHECK(memcmp(f.read_buffer, readbuffer, f.read_len) == 0);
	BOOST_CHECK(f.bs->write_ptr - f.bs->read_ptr == 1);
}

BOOST_AUTO_TEST_CASE(test_read_exactly_called_twice)
{
	readbuffer = "aaaabbbb";
	readbuffer_length = ::strlen(readbuffer);
	F f(READ_COMPLETE_BUFFER);

	int ret = buffered_socket_read_exactly(f.bs, 4, f.read_callback, &f);
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(f.readcallback_called == 2);
	BOOST_CHECK(f.read_len = 4);
	BOOST_CHECK(memcmp(f.read_buffer, readbuffer + 4, f.read_len) == 0);
	BOOST_CHECK(f.bs->write_ptr - f.bs->read_ptr == 0);
}

BOOST_AUTO_TEST_CASE(test_read_exactly_buffer_wrap)
{
	for (unsigned int chunk_size = 1; chunk_size <= CONFIG_MAX_MESSAGE_SIZE; chunk_size++) {
		size_t chunks = (CONFIG_MAX_MESSAGE_SIZE / chunk_size) + 1; 
		char buffer[chunk_size * chunks];
		::memset(buffer, 0, sizeof(buffer));
		readbuffer_length = sizeof(buffer);
		F f(READ_COMPLETE_BUFFER);
		int ret = buffered_socket_read_exactly(f.bs, chunk_size, f.read_callback, &f);
		BOOST_CHECK(ret == 0);
		BOOST_CHECK(f.readcallback_called == chunks);
	}
}

BOOST_AUTO_TEST_CASE(test_read_exactly_nearly_complete_buffer)
{
	F f(READ_FULL);
	size_t read_size = CONFIG_MAX_MESSAGE_SIZE - 1;
	int ret = buffered_socket_read_exactly(f.bs, read_size, f.read_callback, &f);
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(f.readcallback_called == 2);
	BOOST_CHECK(f.read_len = read_size);
	BOOST_CHECK(f.bs->write_ptr - f.bs->read_ptr == 1);
	BOOST_CHECK(f.read_buffer[0] == 'a');
	for (unsigned int i = 1; i < read_size; i++) {
		BOOST_CHECK(f.read_buffer[i] == 'b');
	}
}

BOOST_AUTO_TEST_CASE(test_read_exactly_complete_buffer)
{
	F f(READ_FULL);
	size_t read_size = CONFIG_MAX_MESSAGE_SIZE;
	int ret = buffered_socket_read_exactly(f.bs, read_size, f.read_callback, &f);
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(f.readcallback_called == 2);
	BOOST_CHECK(f.read_len = read_size);
	BOOST_CHECK(f.bs->write_ptr - f.bs->read_ptr == 0);
	for (unsigned int i = 0; i < read_size; i++) {
		BOOST_CHECK(f.read_buffer[i] == 'b');
	}
}

BOOST_AUTO_TEST_CASE(test_read_exactly_more_than_buffer)
{
	F f(READ_FULL);
	size_t read_size = CONFIG_MAX_MESSAGE_SIZE + 1;
	int ret = buffered_socket_read_exactly(f.bs, read_size, f.read_callback, &f);
	BOOST_CHECK(ret == -1);
}

BOOST_AUTO_TEST_CASE(test_read_exactly_read_close)
{
	F f(READ_CLOSE);
	size_t read_size = 4;
	int ret = buffered_socket_read_exactly(f.bs, read_size, f.read_callback, &f);
	BOOST_CHECK(ret == -1);
	BOOST_CHECK(f.readcallback_called == 1);
	BOOST_CHECK(f.read_len == 0);
}

BOOST_AUTO_TEST_CASE(test_read_exactly_read_error)
{
	F f(READ_ERROR);
	size_t read_size = 4;
	int ret = buffered_socket_read_exactly(f.bs, read_size, f.read_callback, &f);
	BOOST_CHECK(ret == -1);
	BOOST_CHECK(f.readcallback_called == 0);
}

BOOST_AUTO_TEST_CASE(test_read_exactly_read_in_callback)
{
	F f(READ_EXACTLY_IN_CALLBACK);
	size_t read_size = 4;
	int ret = buffered_socket_read_exactly(f.bs, read_size, f.read_callback, &f);
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(f.readcallback_called == 2);
}

BOOST_AUTO_TEST_CASE(test_read_exactly_failing_ev_add)
{
	F f(READ_FAILING_EV_ADD);
	size_t read_size = 4;
	int ret = buffered_socket_read_exactly(f.bs, read_size, f.read_callback, &f);
	BOOST_CHECK(ret < 0);
	BOOST_CHECK(f.readcallback_called == 0);
}

BOOST_AUTO_TEST_CASE(test_read_exactly_read_from_eventloop)
{
	readbuffer = "aaaa";
	readbuffer_length = ::strlen(readbuffer);
	F f(READ_FROM_EVENTLOOP);
	int ret = buffered_socket_read_exactly(f.bs, ::strlen(readbuffer), f.read_callback, &f);
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(f.readcallback_called == 0);

	enum eventloop_return cb_ret = f.bs->ev.read_function(&f.bs->ev);
	BOOST_CHECK(cb_ret == EL_CONTINUE_LOOP);
	BOOST_CHECK(f.readcallback_called == 1);
}

BOOST_AUTO_TEST_CASE(test_read_exactly_read_close_from_eventloop)
{
	readbuffer = "aaaa";
	readbuffer_length = ::strlen(readbuffer);
	F f(READ_CLOSE_FROM_EVENTLOOP);
	int ret = buffered_socket_read_exactly(f.bs, ::strlen(readbuffer), f.read_callback, &f);
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(f.readcallback_called == 0);

	enum eventloop_return cb_ret = f.bs->ev.read_function(&f.bs->ev);
	BOOST_CHECK(cb_ret == EL_EVENT_REMOVED);
	BOOST_CHECK(f.readcallback_called == 1);
}

BOOST_AUTO_TEST_CASE(test_read_exactly_read_from_eventloop_fail)
{
	F f(READ_FROM_EVENTLOOP_FAIL);
	size_t read_size = 4;
	int ret = buffered_socket_read_exactly(f.bs, read_size, f.read_callback, &f);
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(f.readcallback_called == 0);
	BOOST_CHECK(!f.error_func_called);

	enum eventloop_return cb_ret = f.bs->ev.read_function(&f.bs->ev);
	BOOST_CHECK(cb_ret == EL_CONTINUE_LOOP);
	BOOST_CHECK(f.readcallback_called == 0);
	BOOST_CHECK(f.error_func_called);
}

BOOST_AUTO_TEST_CASE(test_set_alternate_error_function)
{
	F f(READ_FROM_EVENTLOOP_FAIL);
	size_t read_size = 4;
	int ret = buffered_socket_read_exactly(f.bs, read_size, f.read_callback, &f);
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(f.readcallback_called == 0);
	BOOST_CHECK(!f.error_func_called && !f.error_func_alt_called);

	buffered_socket_set_error(f.bs, f.error_func_alt, &f);
	enum eventloop_return cb_ret = f.bs->ev.read_function(&f.bs->ev);
	BOOST_CHECK(cb_ret == EL_CONTINUE_LOOP);
	BOOST_CHECK(f.readcallback_called == 0);
	BOOST_CHECK(f.error_func_alt_called && !f.error_func_called);
}

BOOST_AUTO_TEST_CASE(test_read_until)
{
	readbuffer = "ccccc\r\ndd";
	readbuffer_length = ::strlen(readbuffer);
	F f(READ_COMPLETE_BUFFER);
	int ret = buffered_socket_read_until(f.bs, "\r\n", f.read_callback, &f);
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(f.readcallback_called == 1);
	BOOST_CHECK(f.read_len == 7);
	BOOST_CHECK(::memcmp(f.read_buffer, readbuffer, f.read_len) == 0);
}

BOOST_AUTO_TEST_CASE(test_read_until_pattern_at_begin)
{
	readbuffer = "\r\ndd";
	readbuffer_length = ::strlen(readbuffer);
	F f(READ_COMPLETE_BUFFER);
	int ret = buffered_socket_read_until(f.bs, "\r\n", f.read_callback, &f);
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(f.readcallback_called == 1);
	BOOST_CHECK(f.read_len == 2);
	BOOST_CHECK(::memcmp(f.read_buffer, readbuffer, f.read_len) == 0);
}

BOOST_AUTO_TEST_CASE(test_read_until_twice)
{
	readbuffer = "eee\r\nffffff\r\n";
	readbuffer_length = ::strlen(readbuffer);
	F f(READ_COMPLETE_BUFFER);
	int ret = buffered_socket_read_until(f.bs, "\r\n", f.read_callback, &f);
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(f.readcallback_called == 2);
	BOOST_CHECK(f.read_len == 8);
	BOOST_CHECK(::memcmp(f.read_buffer, readbuffer + 5, f.read_len) == 0);
}

BOOST_AUTO_TEST_CASE(test_read_until_complete_buffer)
{
	char buffer[CONFIG_MAX_MESSAGE_SIZE];
	::memset(buffer, 'a', sizeof(buffer));
	buffer[CONFIG_MAX_MESSAGE_SIZE -2] = '\r';
	buffer[CONFIG_MAX_MESSAGE_SIZE -1] = '\n';
	readbuffer = buffer;
	readbuffer_length = sizeof(buffer);
	F f(READ_COMPLETE_BUFFER);
	int ret = buffered_socket_read_until(f.bs, "\r\n", f.read_callback, &f);
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(f.readcallback_called == 1);
	BOOST_CHECK(f.read_len == CONFIG_MAX_MESSAGE_SIZE);
	BOOST_CHECK(::memcmp(f.read_buffer, readbuffer, f.read_len) == 0);
}

BOOST_AUTO_TEST_CASE(test_read_until_more_than_buffer)
{
	const char buffer[CONFIG_MAX_MESSAGE_SIZE + 1] = {0};
	readbuffer = buffer;
	readbuffer_length = sizeof(buffer);
	F f(READ_COMPLETE_BUFFER);
	int ret = buffered_socket_read_until(f.bs, "\r\n", f.read_callback, &f);
	BOOST_CHECK(ret == -1);
}

BOOST_AUTO_TEST_CASE(test_read_until_buffer_wrap)
{
	char buffer[2 * CONFIG_MAX_MESSAGE_SIZE];
	::memset(buffer, 0, sizeof(buffer));
	::memset(buffer, 'g', CONFIG_MAX_MESSAGE_SIZE - 5);
	buffer[CONFIG_MAX_MESSAGE_SIZE - 4] = '\r';
	buffer[CONFIG_MAX_MESSAGE_SIZE - 3] = '\n';
	::memset(buffer + CONFIG_MAX_MESSAGE_SIZE - 2, 'f', 8);
	buffer[CONFIG_MAX_MESSAGE_SIZE + 6] = '\r';
	buffer[CONFIG_MAX_MESSAGE_SIZE + 7] = '\n';
	readbuffer = buffer;
	readbuffer_length = sizeof(buffer);
	F f(READ_COMPLETE_BUFFER);
	int ret = buffered_socket_read_until(f.bs, "\r\n", f.read_callback, &f);
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(f.readcallback_called == 2);
}

BOOST_AUTO_TEST_CASE(test_read_until_buffer_wrap_all_sizes)
{
	const char *needle = "\r\n";
	size_t needle_length = ::strlen(needle);
	for (unsigned int chunk_size = needle_length; chunk_size <= CONFIG_MAX_MESSAGE_SIZE; chunk_size++) {
		size_t chunks = (CONFIG_MAX_MESSAGE_SIZE / chunk_size) + 1; 
		char buffer[chunk_size * chunks];
		::memset(buffer, 0, sizeof(buffer));
		for (unsigned int j = 0; j < chunks; j++) {
			unsigned int index = (chunk_size * j) + (chunk_size - needle_length);
			for (unsigned int k = 0; k < needle_length; k++) {
				buffer[index + k] = needle[k];
			}
		}
		readbuffer = buffer;
		readbuffer_length = sizeof(buffer);
		F f(READ_COMPLETE_BUFFER);
		int ret = buffered_socket_read_until(f.bs, needle, f.read_callback, &f);
		BOOST_CHECK(ret == 0);
		BOOST_CHECK(f.readcallback_called == chunks);
	}
}

BOOST_AUTO_TEST_CASE(test_read_until_failing_ev_add)
{
	F f(READ_FAILING_EV_ADD);
	int ret = buffered_socket_read_until(f.bs, "bla", f.read_callback, &f);
	BOOST_CHECK(ret < 0);
	BOOST_CHECK(f.readcallback_called == 0);
}

BOOST_AUTO_TEST_CASE(test_read_until_read_in_callback)
{
	readbuffer = "foo\r\nbar\n\r";
	readbuffer_length = ::strlen(readbuffer);
	F f(READ_UNTIL_IN_CALLBACK);
	int ret = buffered_socket_read_until(f.bs, "\r\n", f.read_callback, &f);
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(f.readcallback_called == 2);
	BOOST_CHECK(f.read_len == 5);
	BOOST_CHECK(::memcmp(f.read_buffer, readbuffer + 5, f.read_len) == 0);
}

BOOST_AUTO_TEST_CASE(test_close)
{
	F f(READ_COMPLETE_BUFFER);
	int ret = buffered_socket_close(f.bs);
	f.bs = NULL;
	BOOST_CHECK(ret == 0);
}
