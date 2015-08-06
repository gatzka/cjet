#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MAIN
#define BOOST_TEST_MODULE read buffer test

#include <arpa/inet.h>
#include <boost/test/unit_test.hpp>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>

#include "cjet_io.h"
#include "linux/io.h"
#include "peer.h"

static const int BADFD = -1;
static const int TOO_MUCH_DATA = 1;
static const int CLIENT_CLOSE = 2;
static const int AGAIN = 3;
static const int SLOW_READ = 4;
static const int FAST_READ = 5;
static const int HANDLE_FAST_PEER = 6;
static const int HANDLE_SLOW_PEER = 7;
static const int WRITE_COMPLETE = 8;
static const int SLOW_WRITE = 9;
static const int INCOMPLETE_WRITE = 10;
static const int INCOMPLETE_WRITELEN_COMPLETE_WRITEMSG = 11;
static const int INCOMPLETE_WRITELEN_INCOMPLETE_WRITEMSG = 12;
static const int DO_NOT_SEND = 13;

extern "C" {

static uint32_t parsed_length = 0;
static char *parsed_msg = NULL;

int parse_message(char *msg, uint32_t length)
{
	parsed_msg = msg;
	parsed_length = length;
	return 0;
}

int add_epoll(int fd, int epoll_fd, void *cookie)
{
	return 0;
}

void remove_epoll(int fd, int epoll_fd)
{
	return;
}

static unsigned char slow_read_counter = 0;
static const char fast_read_msg[] = "HelloWorld";
static const char handle_fast_peer_msg[] = "Hello World!";
static const char handle_slow_peer_msg[] = "Gruess dich Bronko!";
static int handle_fast_peer_first = 0;
static int handle_slow_peer_count = 0;
static unsigned int incomplete_write_counter = 0;
static unsigned int incomplete_write_written_before_blocking = 0;

static char incomplete_write_check_buffer[CONFIG_MAX_MESSAGE_SIZE];
static char *incomplete_write_buffer_ptr = incomplete_write_check_buffer;

int fake_writev(int fd, const struct iovec *iov, int iovcnt)
{
	if (fd == WRITE_COMPLETE) {
	int count = 0;
		for (int i = 0; i < iovcnt; ++i) {
			count += iov[i].iov_len;
		}
		return count;
	}
	if (fd == INCOMPLETE_WRITELEN_COMPLETE_WRITEMSG) {
		static const int incomplete = 1;
		memcpy(incomplete_write_buffer_ptr, iov[0].iov_base, incomplete);
		incomplete_write_buffer_ptr += incomplete;
		return incomplete;
	}
	if (fd == INCOMPLETE_WRITELEN_INCOMPLETE_WRITEMSG) {
		incomplete_write_counter++;
		static const int incomplete = 1;
		memcpy(incomplete_write_buffer_ptr, iov[0].iov_base, incomplete);
		incomplete_write_buffer_ptr += incomplete;
		incomplete_write_written_before_blocking += incomplete;
		return incomplete;
	}

	return 0;
}

int fake_send(int fd, void *buf, size_t count, int flags)
{
	if (fd == BADFD) {
		errno = EBADF;
		return -1;
	}
	if (fd == AGAIN) {
		errno = EAGAIN;
		return -1;
	}
	if (fd == SLOW_WRITE) {
		return 1;
	}
	if (fd == INCOMPLETE_WRITE) {
		if (incomplete_write_counter == 0) {
			incomplete_write_counter++;
			incomplete_write_written_before_blocking = 3;
			return incomplete_write_written_before_blocking;
		} else  {
			errno = EAGAIN;
			return -1;
		}
	}
	if (fd == INCOMPLETE_WRITELEN_COMPLETE_WRITEMSG) {
		memcpy(incomplete_write_buffer_ptr, buf, count);
		incomplete_write_buffer_ptr = incomplete_write_check_buffer;
		return count;
	}

	if (fd == INCOMPLETE_WRITELEN_INCOMPLETE_WRITEMSG) {
		if (incomplete_write_counter == 1) {
			static const int incomplete = 6;
			incomplete_write_counter++;

			memcpy(incomplete_write_buffer_ptr, buf, incomplete);
			incomplete_write_buffer_ptr = incomplete_write_check_buffer;
			incomplete_write_written_before_blocking += incomplete;
			return incomplete;
		} else  {
			errno = EAGAIN;
			return -1;
		}
	}
	if (fd == DO_NOT_SEND) {
		errno = EAGAIN;
		return -1;
	}
	return 0;
}

int fake_read(int fd, void *buf, size_t count)
{
	if (fd == BADFD) {
		errno = EBADF;
		return -1;
	}
	if (fd == CLIENT_CLOSE) {
		return 0;
	}
	if (fd == AGAIN) {
		errno = EAGAIN;
		return -1;
	}

	if (fd == SLOW_READ) {
		char val = ++slow_read_counter;
		if (val % 2 == 0) {
			errno = EAGAIN;
			return -1;
		} else {
			*((char *)buf) = val;
			return 1;
		}
	}

	if (fd == FAST_READ) {
		memcpy(buf, fast_read_msg, strlen(fast_read_msg));
		return strlen(fast_read_msg);
	}

	if (fd == HANDLE_FAST_PEER) {

		if (handle_fast_peer_first == 0) {
			char *write_ptr = (char *)buf;
			uint32_t length = strlen(handle_fast_peer_msg);
			length = htonl(length);
			memcpy(write_ptr, &length, sizeof(length));
			write_ptr += sizeof(length);
			memcpy(write_ptr, handle_fast_peer_msg, sizeof(handle_fast_peer_msg));
			handle_fast_peer_first = 1;
			return sizeof(length) + sizeof(handle_fast_peer_msg);
		} else {
			errno = EAGAIN;
			return -1;
		}
	}

	if (fd == HANDLE_SLOW_PEER) {
		switch (handle_slow_peer_count++) {
			char *write_ptr;
			uint32_t length;
			char *read_ptr;

		case 0:
			write_ptr = (char *)buf;
			length = strlen(handle_slow_peer_msg);
			length = htonl(length);
			memcpy(write_ptr, &length, sizeof(length) - 1);
			return sizeof(length) - 1;

		case 2:
			write_ptr = (char *)buf;
			length = strlen(handle_slow_peer_msg);
			length = htonl(length);
			read_ptr = (char *)&length;
			read_ptr = read_ptr + 3;
			memcpy(write_ptr, read_ptr, 1);
			write_ptr++;
			memcpy(write_ptr, handle_slow_peer_msg, 3);
			return 4;

		case 4:
			write_ptr = (char *)buf;
			memcpy(write_ptr, &handle_slow_peer_msg[3], strlen(handle_slow_peer_msg) - 3);
			return strlen(handle_slow_peer_msg) - 3;

		default:
			errno = EAGAIN;
			return -1;
		}
	}

	return 0;
}

}

BOOST_AUTO_TEST_SUITE(get_read_ptr_test)

BOOST_AUTO_TEST_CASE(wrong_fd)
{
	struct peer *p = alloc_peer(BADFD);
	BOOST_REQUIRE(p != NULL);

	char *read_ptr = get_read_ptr(p, 100);
	intptr_t ret = (intptr_t)read_ptr;
	BOOST_CHECK(ret == IO_ERROR);

	free_peer(p);
}

BOOST_AUTO_TEST_CASE(too_much_data_requested)
{
	struct peer *p = alloc_peer(TOO_MUCH_DATA);
	BOOST_REQUIRE(p != NULL);

	char *read_ptr = get_read_ptr(p, CONFIG_MAX_MESSAGE_SIZE + 1);
	BOOST_CHECK(read_ptr == NULL);

	free_peer(p);
}

BOOST_AUTO_TEST_CASE(client_closed_connection)
{
	struct peer *p = alloc_peer(CLIENT_CLOSE);
	BOOST_REQUIRE(p != NULL);

	char *read_ptr = get_read_ptr(p, CONFIG_MAX_MESSAGE_SIZE);
	intptr_t ret = (intptr_t)read_ptr;
	BOOST_CHECK(ret == IO_CLOSE);

	free_peer(p);
}

BOOST_AUTO_TEST_CASE(eagain)
{
	struct peer *p = alloc_peer(AGAIN);
	BOOST_REQUIRE(p != NULL);

	char *read_ptr = get_read_ptr(p, CONFIG_MAX_MESSAGE_SIZE);
	BOOST_CHECK(read_ptr == (char *)IO_WOULD_BLOCK);

	free_peer(p);
}

BOOST_AUTO_TEST_CASE(slow_read)
{
	uint32_t value;

	struct peer *p = alloc_peer(SLOW_READ);
	BOOST_REQUIRE(p != NULL);

	slow_read_counter = 0;

	char *read_ptr = get_read_ptr(p, sizeof(value));
	BOOST_CHECK(read_ptr == (char *)IO_WOULD_BLOCK);
	read_ptr = get_read_ptr(p, sizeof(value));
	BOOST_CHECK(read_ptr == (char *)IO_WOULD_BLOCK);
	read_ptr = get_read_ptr(p, sizeof(value));
	BOOST_CHECK(read_ptr == (char *)IO_WOULD_BLOCK);
	read_ptr = get_read_ptr(p, sizeof(value));
	if ((read_ptr != NULL) && (read_ptr != (char *)IO_WOULD_BLOCK)) {
		memcpy(&value, read_ptr, sizeof(value));
		BOOST_CHECK(ntohl(value) == 0x01030507);
	} else {
		BOOST_FAIL("read_ptr either null or IO_WOULD_BLOCK!");
	}
	free_peer(p);
}

BOOST_AUTO_TEST_CASE(fast_read)
{
	static const int read_len = 5;
	char buffer[read_len + 1];

	struct peer *p = alloc_peer(FAST_READ);
	if (p != NULL) {
		char *read_ptr = get_read_ptr(p, read_len);
		if ((read_ptr != NULL) && (read_ptr != (char *)IO_WOULD_BLOCK)) {
			strncpy(buffer, read_ptr, read_len);
			buffer[read_len] = '\0';
			BOOST_CHECK(strcmp(buffer, "Hello") == 0);
		} else {
			BOOST_FAIL("read_ptr either null or IO_WOULD_BLOCK!");
		}

		read_ptr = get_read_ptr(p, read_len);
		if ((read_ptr != NULL) && (read_ptr != (char *)IO_WOULD_BLOCK)) {
			strncpy(buffer, read_ptr, read_len);
			buffer[read_len] = '\0';
			BOOST_CHECK(strcmp(buffer, "World") == 0);
		} else {
			BOOST_FAIL("read_ptr either null or IO_WOULD_BLOCK!");
		}
		free_peer(p);
	} else {
		BOOST_FAIL("Could not allocate a peer!");
	}
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(handle_all_peer_operations_test)

BOOST_AUTO_TEST_CASE(fast_peer)
{
	struct peer *p = alloc_peer(HANDLE_FAST_PEER);
	BOOST_REQUIRE(p != NULL);

	int ret = handle_all_peer_operations(p);
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(parsed_length == strlen(handle_fast_peer_msg));
	BOOST_CHECK(strncmp(parsed_msg, handle_fast_peer_msg, parsed_length) == 0);

	free_peer(p);
}

BOOST_AUTO_TEST_CASE(slow_peer)
{
	parsed_length = 0;
	parsed_msg = NULL;

	struct peer *p = alloc_peer(HANDLE_SLOW_PEER);
	if (p != NULL) {
		int ret = handle_all_peer_operations(p);
		BOOST_CHECK(parsed_msg == NULL);
		BOOST_CHECK(ret == 0);
		BOOST_CHECK(p->op == READ_MSG_LENGTH);

		ret = handle_all_peer_operations(p);
		BOOST_CHECK(parsed_msg == NULL);
		BOOST_CHECK(ret == 0);
		BOOST_CHECK(p->op == READ_MSG);

		ret = handle_all_peer_operations(p);
		BOOST_REQUIRE(parsed_msg != NULL);
		BOOST_CHECK(ret == 0);
		BOOST_CHECK(p->op == READ_MSG_LENGTH);
		BOOST_CHECK(parsed_length == strlen(handle_slow_peer_msg));
		if (parsed_msg != NULL) {
			BOOST_CHECK(strncmp(parsed_msg, handle_slow_peer_msg, parsed_length) == 0);
		} else {
			BOOST_ERROR("no parsed message!");
		}

		free_peer(p);
	} else {
		BOOST_FAIL("Could not allocate a peer!");
	}
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(copy_msg_to_write_buffer_test)

BOOST_AUTO_TEST_CASE(copy_msg_all)
{
	struct peer *p = alloc_peer(BADFD);
	BOOST_REQUIRE(p != NULL);

	const char message[] = "Hello World!";
	uint32_t len = ::strlen(message);
	uint32_t len_be = htonl(len);
	int ret = copy_msg_to_write_buffer(p, message, len_be, 0);
	BOOST_CHECK(ret == 0);

	char *read_back_ptr = p->write_buffer;
	uint32_t readback_len_be32;
	memcpy(&readback_len_be32, read_back_ptr, sizeof(readback_len_be32));
	uint32_t readback_len = ntohl(readback_len_be32);
	BOOST_CHECK(readback_len == len);

	read_back_ptr += sizeof(readback_len_be32);
	ret = ::strncmp(read_back_ptr, message, len);
	BOOST_CHECK(ret == 0);

	free_peer(p);
}

BOOST_AUTO_TEST_CASE(copy_msg_len_already_written)
{
	struct peer *p = alloc_peer(BADFD);
	BOOST_REQUIRE(p != NULL);

	const char message[] = "Hello World!";
	uint32_t len = ::strlen(message);
	uint32_t len_be = htonl(len);
	int ret = copy_msg_to_write_buffer(p, message, len_be, sizeof(len_be));
	BOOST_CHECK(ret == 0);

	char *read_back_ptr = p->write_buffer;
	ret = ::strncmp(read_back_ptr, message, len);
	BOOST_CHECK(ret == 0);

	free_peer(p);
}

BOOST_AUTO_TEST_CASE(copy_msg_len_written_partly)
{
	struct peer *p = alloc_peer(BADFD);
	BOOST_REQUIRE(p != NULL);

	static const size_t already_written = 3;
	unsigned int len_part = sizeof(uint32_t) - already_written;

	char message[CONFIG_MAX_MESSAGE_SIZE - len_part];
	for (unsigned int i = 0; i < sizeof(message); ++i) {
		message[i] = (i + 13) & 0xff;
	}
	uint32_t len = sizeof(message);
	uint32_t len_be = htonl(len);
	int ret = copy_msg_to_write_buffer(p, message, len_be, already_written);
	BOOST_CHECK(ret == 0);

	char *read_back_ptr = p->write_buffer;
	uint32_t readback_len_be32;

	::memcpy(&readback_len_be32, read_back_ptr, len_part);
	ret = ::memcmp(&readback_len_be32, (char*)(&len_be) + already_written, len_part);
	BOOST_CHECK(ret == 0);

	read_back_ptr += len_part;
	ret = memcmp(read_back_ptr, message, (CONFIG_MAX_MESSAGE_SIZE - len_part));
	BOOST_CHECK(ret == 0);

	free_peer(p);
}

BOOST_AUTO_TEST_CASE(copy_msg_msg_written_partly)
{
	struct peer *p = alloc_peer(BADFD);
	BOOST_REQUIRE(p != NULL);

	unsigned int msg_part_already_written = 3;

	static const char message[] = "Hello World!";
	uint32_t len = ::strlen(message);
	uint32_t len_be = htonl(len);
	int ret = copy_msg_to_write_buffer(p, message, len_be, sizeof(len_be) + msg_part_already_written);
	BOOST_CHECK(ret == 0);

	char *read_back_ptr = p->write_buffer;
	ret = ::strncmp(read_back_ptr, message + msg_part_already_written, len - msg_part_already_written);
	BOOST_CHECK(ret == 0);

	free_peer(p);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(send_buffer_test)

BOOST_AUTO_TEST_CASE(wrong_fd)
{
	struct peer *p = alloc_peer(BADFD);
	if (p != NULL) {
		p->to_write = 10;
		int ret = send_buffer(p);
		BOOST_CHECK(ret == -1);

		free_peer(p);
	} else {
		BOOST_FAIL("Could not allocate a peer!");
	}
}

BOOST_AUTO_TEST_CASE(write_blocks)
{
	char buffer[10];
	struct peer *p = alloc_peer(AGAIN);
	if (p != NULL) {
		p->to_write = sizeof(buffer);
		int ret = send_buffer(p);
		BOOST_CHECK(ret == IO_WOULD_BLOCK);
		BOOST_CHECK(p->op == WRITE_MSG);

		free_peer(p);
	} else {
		BOOST_FAIL("Could not allocate a peer!");
	}
}

BOOST_AUTO_TEST_CASE(incomplete_write)
{
	incomplete_write_buffer_ptr = incomplete_write_check_buffer;
	incomplete_write_counter = 0;
	incomplete_write_written_before_blocking = 0;

	struct peer *p = alloc_peer(INCOMPLETE_WRITE);
	if (p != NULL) {
		static char sw_message[] = "HelloWorld!";
		uint32_t len_be = htonl(::strlen(sw_message));
		int ret = copy_msg_to_write_buffer(p, sw_message, len_be, 0);
		BOOST_REQUIRE(ret == 0);

		ret = send_buffer(p);
		BOOST_CHECK(ret == IO_WOULD_BLOCK);
		BOOST_CHECK(p->op == WRITE_MSG);

		static char check_buffer[sizeof(sw_message) + sizeof(len_be)];
		char *buf_ptr = check_buffer;
		memcpy(buf_ptr, &len_be, sizeof(len_be));
		buf_ptr += sizeof(len_be);
		memcpy(buf_ptr, sw_message, strlen(sw_message));

		ret = memcmp(p->write_buffer, check_buffer + incomplete_write_written_before_blocking, p->to_write);
		BOOST_CHECK(ret == 0);

		free_peer(p);
	} else {
		BOOST_FAIL("Could not allocate a peer!");
	}
}

BOOST_AUTO_TEST_CASE(slow_write)
{
	struct peer *p = alloc_peer(SLOW_WRITE);
	BOOST_REQUIRE(p != NULL);

	static char sw_message[] = "HelloWorld!";
	int ret = copy_msg_to_write_buffer(p, sw_message, htonl(::strlen(sw_message)), 0);
	BOOST_REQUIRE(ret == 0);

	ret = send_buffer(p);
	BOOST_CHECK(ret == 0);

	free_peer(p);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(send_message_test)

BOOST_AUTO_TEST_CASE(complete)
{
	struct peer *p = alloc_peer(WRITE_COMPLETE);
	BOOST_REQUIRE(p != NULL);

	static char message[] = "HelloWorld!";
	int ret = send_message(p, message, ::strlen(message));
	BOOST_CHECK(ret == 0);

	free_peer(p);
}

BOOST_AUTO_TEST_CASE(max_message_length)
{
	struct peer *p = alloc_peer(DO_NOT_SEND);
	if (p != NULL) {
		p->op = WRITE_MSG;

		static char message[CONFIG_MAX_WRITE_BUFFER_SIZE - sizeof(uint32_t) + 1];
		memset(message, 0x42, sizeof(message));
		message[CONFIG_MAX_WRITE_BUFFER_SIZE - sizeof(uint32_t)] = '\0';
		int ret = send_message(p, message, ::strlen(message));
		BOOST_CHECK(ret == 0);

		free_peer(p);
	} else {
		BOOST_FAIL("Could not allocate a peer!");
	}
}

BOOST_AUTO_TEST_CASE(message_too_large)
{
	struct peer *p = alloc_peer(BADFD);
	if (p != NULL) {
		p->op = WRITE_MSG;

		static char message[CONFIG_MAX_WRITE_BUFFER_SIZE - sizeof(uint32_t) + 2];
		memset(message, 0x42, sizeof(message));
		message[CONFIG_MAX_WRITE_BUFFER_SIZE - sizeof(uint32_t) + 1] = '\0';
		int ret = send_message(p, message, ::strlen(message));
		BOOST_CHECK(ret == -1);

		free_peer(p);
	} else {
		BOOST_FAIL("Could not allocate a peer!");
	}
}

BOOST_AUTO_TEST_CASE(incomplete_writelen_complete_writemsg)
{
	incomplete_write_counter = 0;
	incomplete_write_buffer_ptr = incomplete_write_check_buffer;

	struct peer *p = alloc_peer(INCOMPLETE_WRITELEN_COMPLETE_WRITEMSG);
	BOOST_REQUIRE(p != NULL);

	static char message[] = "HelloWorld!";
	int ret = send_message(p, message, ::strlen(message));
	BOOST_CHECK(ret == 0);

	static char check_buffer[CONFIG_MAX_MESSAGE_SIZE];
	uint32_t len_be = htonl(::strlen(message));
	char *buf_ptr = check_buffer;

	memcpy(buf_ptr, &len_be, sizeof(len_be));
	buf_ptr += sizeof(len_be);
	memcpy(buf_ptr, message, strlen(message));

	ret = memcmp(incomplete_write_check_buffer, check_buffer, strlen(message) + sizeof(len_be));
	BOOST_CHECK(ret == 0);

	free_peer(p);
}

BOOST_AUTO_TEST_CASE(incomplete_writelen_incomplete_writemsg)
{
	incomplete_write_buffer_ptr = incomplete_write_check_buffer;
	incomplete_write_counter = 0;
	incomplete_write_written_before_blocking = 0;

	struct peer *p = alloc_peer(INCOMPLETE_WRITELEN_INCOMPLETE_WRITEMSG);
	if (p != NULL) {
		static char message[] = "HelloWorld!";
		int ret = send_message(p, message, ::strlen(message));
		BOOST_CHECK(ret == 0);
		BOOST_CHECK(p->op == WRITE_MSG);

		static char check_buffer[CONFIG_MAX_MESSAGE_SIZE];
		uint32_t len_be = htonl(::strlen(message));
		char *buf_ptr = check_buffer;

		memcpy(buf_ptr, &len_be, sizeof(len_be));
		buf_ptr += sizeof(len_be);
		memcpy(buf_ptr, message, strlen(message));

		ret = memcmp(incomplete_write_check_buffer, check_buffer, incomplete_write_written_before_blocking);
		BOOST_CHECK(ret == 0);

		free_peer(p);
	} else {
		BOOST_FAIL("Could not allocate a peer!");
	}
}

BOOST_AUTO_TEST_SUITE_END()
