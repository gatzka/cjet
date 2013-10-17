#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MAIN
#define BOOST_TEST_MODULE parse JSON
#include <boost/test/unit_test.hpp>

#include "../parse.h"

static const char correct_json[] = "{\"id\": 7384,\"method\": \"add\",\"params\":{\"path\": \"foo/bar/state\",\"value\": 123}}";
static const char wrong_json[] = "{\"id\": 7384,\"method\": add\",\"params\":{\"path\": \"foo/bar/state\",\"value\": 123}}";
static const char json_no_method[] = "{\"id\": 7384,\"meth\": \"add\",\"params\":{\"path\": \"foo/bar/state\",\"value\": 123}}";
static const char json_no_string_method[] = "{\"id\": 7384,\"method\": 123,\"params\":{\"path\": \"foo/bar/state\",\"value\": 123}}";
static const char json_unsupported_method[] = "{\"id\": 7384,\"method\": \"horst\",\"params\":{\"path\": \"foo/bar/state\",\"value\": 123}}";

BOOST_AUTO_TEST_CASE(parse_correct_json)
{
	int ret = parse_message(correct_json, strlen(correct_json));
	BOOST_CHECK(ret == 0);
}

BOOST_AUTO_TEST_CASE(length_too_long)
{
	int ret = parse_message(correct_json, strlen(correct_json) + 1);
	BOOST_CHECK(ret == -1);
}

BOOST_AUTO_TEST_CASE(length_too_short)
{
	int ret = parse_message(correct_json, strlen(correct_json) -1);
	BOOST_CHECK(ret == -1);
}

BOOST_AUTO_TEST_CASE(parse_wrong_json)
{
	int ret = parse_message(wrong_json, strlen(wrong_json));
	BOOST_CHECK(ret == -1);
}

BOOST_AUTO_TEST_CASE(no_method)
{
	int ret = parse_message(json_no_method, strlen(json_no_method));
	BOOST_CHECK(ret == -1);
}

BOOST_AUTO_TEST_CASE(no_string_method)
{
	int ret = parse_message(json_no_string_method, strlen(json_no_string_method));
	BOOST_CHECK(ret == -1);
}

BOOST_AUTO_TEST_CASE(unsupported_method)
{
	int ret = parse_message(json_unsupported_method, strlen(json_unsupported_method));
	BOOST_CHECK(ret == -1);
}
