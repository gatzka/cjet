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

#include "../peer.h"

extern "C" {

int parse_message(char *msg, uint32_t length)
{
	return 0;
}

ssize_t fake_read(int fd, void *buf, size_t count)
{
	if (fd == -1) {
		errno = EBADF;
		return -1;
	}
	return 0;
}

}

BOOST_AUTO_TEST_CASE(wrong_fd)
{
	struct peer *p = alloc_peer(-1);
	BOOST_REQUIRE(p != NULL);

	char *read_ptr = get_read_ptr(p, 100);
	BOOST_CHECK(read_ptr == NULL);

	free_peer(p);
}

