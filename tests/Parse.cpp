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
#define BOOST_TEST_MODULE parse JSON
#include <boost/test/unit_test.hpp>

#include "../parse.h"

static const char correct_json[] = "{\"id\": 7384,\"method\": \"add\",\"params\":{\"path\": \"foo/bar/state\",\"value\": 123}}";
static const char wrong_json[] = "{\"id\": 7384,\"method\": add\",\"params\":{\"path\": \"foo/bar/state\",\"value\": 123}}";

BOOST_AUTO_TEST_CASE(parse_correct_json)
{
	int ret = parse_message(correct_json, strlen(correct_json));
	BOOST_CHECK(ret == 0);
}

BOOST_AUTO_TEST_CASE(lenth_too_long)
{
	int ret = parse_message(correct_json, strlen(correct_json) + 1);
	BOOST_CHECK(ret == -1);
}

BOOST_AUTO_TEST_CASE(lenth_too_short)
{
	int ret = parse_message(correct_json, strlen(correct_json) -1);
	BOOST_CHECK(ret == -1);
}

BOOST_AUTO_TEST_CASE(parse_wrong_json)
{
	int ret = parse_message(wrong_json, strlen(wrong_json));
	BOOST_CHECK(ret == -1);
}
