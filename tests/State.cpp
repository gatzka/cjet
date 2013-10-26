#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MAIN
#define BOOST_TEST_MODULE state

#include <boost/test/unit_test.hpp>

#include "../peer.h"
#include "../state.h"

extern "C" {

	int parse_message(const char *msg, uint32_t length, struct peer *p)
	{
		return 0;
	}

	int fake_read(int fd, void *buf, size_t count)
	{
		return 0;
	}

	int fake_send(int fd, void *buf, size_t count, int flags)
	{
		return count;
	}
}

BOOST_AUTO_TEST_CASE(add_state)
{
	create_setter_hashtable();
	struct peer *p = alloc_peer(-1);
	cJSON *value = cJSON_CreateNumber(1234);

	cJSON *error = add_state_to_peer(p, "/foo/bar/", value);
	BOOST_CHECK(error == NULL);

	cJSON_Delete(value);
	free_peer(p);
	delete_setter_hashtable();
}

BOOST_AUTO_TEST_CASE(add_duplicate_state)
{
	create_setter_hashtable();
	struct peer *p = alloc_peer(-1);

	cJSON *value = cJSON_CreateNumber(1234);

	cJSON *error = add_state_to_peer(p, "/foo/bar/", value);
	BOOST_CHECK(error == NULL);

	error = add_state_to_peer(p, "/foo/bar/", value);
	BOOST_CHECK(error != NULL);
	cJSON *code = cJSON_GetObjectItem(error, "code");
	BOOST_REQUIRE(code != NULL);
	BOOST_CHECK(code->type == cJSON_Number);
	BOOST_CHECK(code->valueint == -32602);
	cJSON *message = cJSON_GetObjectItem(error, "message");
	BOOST_REQUIRE(message != NULL);
	BOOST_CHECK(message->type == cJSON_String);
	BOOST_CHECK(strcmp(message->valuestring, "Invalid params") == 0);

	cJSON_Delete(error);

	cJSON_Delete(value);
	free_peer(p);
	delete_setter_hashtable();
}
