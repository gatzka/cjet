#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MAIN
#define BOOST_TEST_MODULE state

#include <boost/test/unit_test.hpp>
#include <sys/uio.h>

#include "peer.h"
#include "state.h"

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

	int fake_writev(int fd, const struct iovec *iov, int iovcnt)
	{
		int count = 0;
		for (int i = 0; i < iovcnt; ++i) {
			count += iov[i].iov_len;
		}
		return count;
	}
}

struct F {
	F()
	{
		create_state_hashtable();
		p = alloc_peer(-1);
	}
	~F()
	{
		free_peer(p);
		delete_state_hashtable();
	}

	struct peer *p;
};

static void check_invalid_params(cJSON *error)
{
	cJSON *code = cJSON_GetObjectItem(error, "code");
	BOOST_REQUIRE(code != NULL);
	BOOST_CHECK(code->type == cJSON_Number);
	BOOST_CHECK(code->valueint == -32602);
	cJSON *message = cJSON_GetObjectItem(error, "message");
	BOOST_REQUIRE(message != NULL);
	BOOST_CHECK(message->type == cJSON_String);
	BOOST_CHECK(strcmp(message->valuestring, "Invalid params") == 0);
}

BOOST_FIXTURE_TEST_CASE(add_state, F)
{
	const char *path = "/foo/bar/";
	int state_value = 12345;
	cJSON *value = cJSON_CreateNumber(state_value);

	cJSON *error = add_state_to_peer(p, path, value);
	BOOST_CHECK(error == NULL);

	cJSON_Delete(value);

	struct state *s = get_state(path);
	BOOST_CHECK(s->value->valueint == state_value);
}

BOOST_FIXTURE_TEST_CASE(add_duplicate_state, F)
{
	cJSON *value = cJSON_CreateNumber(1234);

	cJSON *error = add_state_to_peer(p, "/foo/bar/", value);
	BOOST_CHECK(error == NULL);

	error = add_state_to_peer(p, "/foo/bar/", value);
	BOOST_REQUIRE(error != NULL);
	check_invalid_params(error);
	cJSON_Delete(error);
	cJSON_Delete(value);
}

BOOST_FIXTURE_TEST_CASE(delete_single_state, F)
{
	const char path[] = "/foo/bar/";
	cJSON *value = cJSON_CreateNumber(1234);
	cJSON *error = add_state_to_peer(p, path, value);
	BOOST_CHECK(error == NULL);

	cJSON_Delete(value);

	error = remove_state_from_peer(p, path);
	BOOST_CHECK(error == NULL);
}

BOOST_FIXTURE_TEST_CASE(delete_nonexisting_state, F)
{
	const char path[] = "/foo/bar/";
	cJSON *error = remove_state_from_peer(p, path);
	BOOST_CHECK(error != NULL);
	check_invalid_params(error);
	cJSON_Delete(error);
}

BOOST_FIXTURE_TEST_CASE(double_free_state, F)
{
	const char path[] = "/foo/bar/";
	cJSON *value = cJSON_CreateNumber(1234);
	cJSON *error = add_state_to_peer(p, path, value);
	BOOST_CHECK(error == NULL);

	cJSON_Delete(value);

	error = remove_state_from_peer(p, path);
	BOOST_CHECK(error == NULL);

	error = remove_state_from_peer(p, path);
	BOOST_CHECK(error != NULL);
	check_invalid_params(error);
	cJSON_Delete(error);
}

BOOST_FIXTURE_TEST_CASE(change, F)
{
	const char path[] = "/foo/bar/";
	cJSON *value = cJSON_CreateNumber(1234);
	cJSON *error = add_state_to_peer(p, path, value);
	BOOST_CHECK(error == NULL);
	cJSON_Delete(value);

	cJSON *new_value = cJSON_CreateNumber(4321);
	error = change_state(path, new_value);
	BOOST_CHECK(error == NULL);
	cJSON_Delete(new_value);

	struct state *s = get_state(path);
	BOOST_CHECK(s->value->valueint == 4321);
}

BOOST_FIXTURE_TEST_CASE(change_wrong_path, F)
{
	cJSON *value = cJSON_CreateNumber(1234);
	cJSON *error = add_state_to_peer(p, "/foo/bar/", value);
	BOOST_CHECK(error == NULL);
	cJSON_Delete(value);

	cJSON *new_value = cJSON_CreateNumber(4321);
	error = change_state("/bar/foo/", new_value);
	BOOST_CHECK(error != NULL);
	cJSON_Delete(new_value);
	check_invalid_params(error);
	cJSON_Delete(error);
}
