#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MAIN
#define BOOST_TEST_MODULE parse JSON
#include <boost/test/unit_test.hpp>

#include "../parse.h"
#include "../cJSON.h"

extern "C" {

	int fake_read(int fd, void *buf, size_t count)
	{
		return 0;
	}

	int fake_send(int fd, void *buf, size_t count, int flags)
	{
		return count;
	}
}

static const char correct_json[] = "{\"id\": 7384,\"method\": \"add\",\"params\":{\"path\": \"foo/bar/state\",\"value\": 123}}";
static const char wrong_json[] = "{\"id\": 7384,\"method\": add\",\"params\":{\"path\": \"foo/bar/state\",\"value\": 123}}";
static const char json_no_method[] = "{\"id\": 7384,\"meth\": \"add\",\"params\":{\"path\": \"foo/bar/state\",\"value\": 123}}";
static const char json_no_string_method[] = "{\"id\": 7384,\"method\": 123,\"params\":{\"path\": \"foo/bar/state\",\"value\": 123}}";
static const char json_two_method[] = "[{\"id\": 7384,\"method\": \"add\",\"params\":{\"path\": \"foo/bar/state\",\"value\": 123}}, {\"id\": 7384,\"method\": \"add\",\"params\":{\"path\": \"foo/state\",\"value\": 321}}]";
static const char json_unsupported_method[] = "{\"id\": 7384,\"method\": \"horst\",\"params\":{\"path\": \"foo/bar/state\",\"value\": 123}}";
static const char wrong_jet_array[] = "[1, 2]";


BOOST_AUTO_TEST_CASE(parse_correct_json)
{
	struct peer *p = alloc_peer(-1);
	int ret = parse_message(correct_json, strlen(correct_json), p);
	BOOST_CHECK(ret == 0);
	free_peer(p);
}

BOOST_AUTO_TEST_CASE(length_too_long)
{
	int ret = parse_message(correct_json, strlen(correct_json) + 1, NULL);
	BOOST_CHECK(ret == -1);
}

BOOST_AUTO_TEST_CASE(length_too_short)
{
	int ret = parse_message(correct_json, strlen(correct_json) - 1, NULL);
	BOOST_CHECK(ret == -1);
}

BOOST_AUTO_TEST_CASE(parse_wrong_json)
{
	int ret = parse_message(wrong_json, strlen(wrong_json), NULL);
	BOOST_CHECK(ret == -1);
}

BOOST_AUTO_TEST_CASE(no_method)
{
	int ret = parse_message(json_no_method, strlen(json_no_method), NULL);
	BOOST_CHECK(ret == -1);
}

BOOST_AUTO_TEST_CASE(no_string_method)
{
	int ret = parse_message(json_no_string_method, strlen(json_no_string_method), NULL);
	BOOST_CHECK(ret == -1);
}

BOOST_AUTO_TEST_CASE(unsupported_method)
{
	int ret = parse_message(json_unsupported_method, strlen(json_unsupported_method), NULL);
	BOOST_CHECK(ret == -1);
}

BOOST_AUTO_TEST_CASE(two_method)
{
	struct peer *p = alloc_peer(-1);
	int ret = parse_message(json_two_method, strlen(json_two_method), p);
	BOOST_CHECK(ret == 0);
	free_peer(p);
}

BOOST_AUTO_TEST_CASE(wrong_array)
{
	int ret = parse_message(wrong_jet_array, strlen(wrong_jet_array), NULL);
	BOOST_CHECK(ret == -1);
}

