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

extern "C" {

int parse_message(char *msg, uint32_t length)
{
	return 0;
}

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
