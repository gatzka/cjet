/*
 * Copyright (C) 2007 Hottinger Baldwin Messtechnik GmbH
 * Im Tiefen See 45
 * 64293 Darmstadt
 * Germany
 * http://www.hbm.com
 * All rights reserved
 *
 * The copyright to the computer program(s) herein is the property of
 * Hottinger Baldwin Messtechnik GmbH (HBM), Germany. The program(s)
 * may be used and/or copied only with the written permission of HBM
 * or in accordance with the terms and conditions stipulated in the
 * agreement/contract under which the program(s) have been supplied.
 * This copyright notice must not be removed.
 *
 * This Software is licenced by the
 * "General supply and license conditions for software"
 * which is part of the standard terms and conditions of sale from HBM.
*/

/*
$HeadURL:$
$Revision:$
$Author:$
$Date:$
*/
/** @file */

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MAIN
#define BOOST_TEST_MODULE read buffer test
#include <boost/test/unit_test.hpp>
#include <errno.h>
#include <stdint.h>

#include "../config.h"
#include "../peer.h"

static const int BADFD = -1;
static const int TOO_MUCH_DATA = 1;
static const int CLIENT_CLOSE = 2;
static const int AGAIN = 3;
static const int SLOW_READ = 4;
static const int FAST_READ = 5;
static const int HANDLE_FAST_PEER = 6;

extern "C" {

static uint32_t parsed_length = 0;
static char *parsed_msg = NULL;

int parse_message(char *msg, uint32_t length)
{
	parsed_msg = msg;
	parsed_length = length;
	return 0;
}

static unsigned char slow_read_counter = 0;
static const char fast_read_msg[] = "HelloWorld";
static const char handle_fast_peer_msg[] = "Hello World!";
static int handle_fast_peer_first = 0;

ssize_t fake_read(int fd, void *buf, size_t count)
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
			length = htobe32(length);
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

}

}

BOOST_AUTO_TEST_CASE(wrong_fd)
{
	struct peer *p = alloc_peer(BADFD);
	BOOST_REQUIRE(p != NULL);

	char *read_ptr = get_read_ptr(p, 100);
	BOOST_CHECK(read_ptr == NULL);

	free_peer(p);
}

BOOST_AUTO_TEST_CASE(too_much_data_requested)
{
	struct peer *p = alloc_peer(TOO_MUCH_DATA);
	BOOST_REQUIRE(p != NULL);

	char *read_ptr = get_read_ptr(p, MAX_MESSAGE_SIZE + 1);
	BOOST_CHECK(read_ptr == NULL);

	free_peer(p);
}

BOOST_AUTO_TEST_CASE(client_closed_connection)
{
	struct peer *p = alloc_peer(CLIENT_CLOSE);
	BOOST_REQUIRE(p != NULL);

	char *read_ptr = get_read_ptr(p, MAX_MESSAGE_SIZE);
	BOOST_CHECK(read_ptr == NULL);

	free_peer(p);
}

BOOST_AUTO_TEST_CASE(eagain)
{
	struct peer *p = alloc_peer(AGAIN);
	BOOST_REQUIRE(p != NULL);

	char *read_ptr = get_read_ptr(p, MAX_MESSAGE_SIZE);
	BOOST_CHECK(read_ptr == (char *)-1);

	free_peer(p);
}

BOOST_AUTO_TEST_CASE(slow_read)
{
	uint32_t value;

	struct peer *p = alloc_peer(SLOW_READ);
	BOOST_REQUIRE(p != NULL);

	slow_read_counter = 0;

	char *read_ptr = get_read_ptr(p, sizeof(value));
	BOOST_CHECK(read_ptr == (char *)-1);
	read_ptr = get_read_ptr(p, sizeof(value));
	BOOST_CHECK(read_ptr == (char *)-1);
	read_ptr = get_read_ptr(p, sizeof(value));
	BOOST_CHECK(read_ptr == (char *)-1);
	read_ptr = get_read_ptr(p, sizeof(value));
	BOOST_CHECK((read_ptr != NULL) && (read_ptr != (char *)-1));
	memcpy(&value, read_ptr, sizeof(value));
	BOOST_CHECK(be32toh(value) == 0x01030507);
	free_peer(p);
}

BOOST_AUTO_TEST_CASE(fast_read)
{
	uint32_t value;
	static const int read_len = 5;
	char buffer[read_len + 1];

	struct peer *p = alloc_peer(FAST_READ);
	BOOST_REQUIRE(p != NULL);

	char *read_ptr = get_read_ptr(p, read_len);
	BOOST_CHECK((read_ptr != NULL) && (read_ptr != (char *)-1));

	strncpy(buffer, read_ptr, read_len);
	buffer[read_len] = '\0';
	BOOST_CHECK(strcmp(buffer, "Hello") == 0);

	read_ptr = get_read_ptr(p, read_len);
	BOOST_CHECK((read_ptr != NULL) && (read_ptr != (char *)-1));

	strncpy(buffer, read_ptr, read_len);
	buffer[read_len] = '\0';
	BOOST_CHECK(strcmp(buffer, "World") == 0);

	free_peer(p);
}

BOOST_AUTO_TEST_CASE(handle_fast_peer)
{
	struct peer *p = alloc_peer(HANDLE_FAST_PEER);
	BOOST_REQUIRE(p != NULL);

	int ret = handle_all_peer_operations(p);
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(parsed_length == strlen(handle_fast_peer_msg));
	BOOST_CHECK(strncmp(parsed_msg, handle_fast_peer_msg, parsed_length) == 0);

	free_peer(p);
}
