#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MAIN
#define BOOST_TEST_MODULE state

#include <arpa/inet.h>
#include <boost/test/unit_test.hpp>
#include <sys/uio.h>

#include "peer.h"
#include "router.h"
#include "state.h"

static char send_buffer[100000];

extern "C" {
	int send_message(struct peer *p, const char *rendered, size_t len)
	{
		memcpy(send_buffer, rendered, len);
		return 0;
	}
	int add_io(struct peer *p)
	{
		return 0;
	}

	void remove_io(const struct peer *p)
	{
		return;
	}
}

static cJSON *parse_send_buffer(void)
{
	char *read_ptr = send_buffer;
	const char *end_parse;
	cJSON *root = cJSON_ParseWithOpts(read_ptr, &end_parse, 0);
	return root;
}

static cJSON *create_response_from_message(cJSON *routed_message)
{
	cJSON *id = cJSON_GetObjectItem(routed_message, "id");
	cJSON *duplicated_id = cJSON_Duplicate(id, 1);

	cJSON *response = cJSON_CreateObject();
	cJSON_AddItemToObject(response, "id", duplicated_id);
	cJSON *result = cJSON_CreateString("");
	cJSON_AddItemToObject(response, "result", result);
	return response;
}

static cJSON *get_result_from_response(cJSON *response)
{
	cJSON *result = cJSON_GetObjectItem(response, "result");
	if (result != NULL) {
		return result;
	}
	cJSON *error = cJSON_GetObjectItem(response, "error");
	if (error != NULL) {
		return result;
	}
	return NULL;
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

	int ret = remove_state_from_peer(p, path);
	BOOST_CHECK(ret == 0);
}

BOOST_FIXTURE_TEST_CASE(delete_nonexisting_state, F)
{
	const char path[] = "/foo/bar/";
	int ret = remove_state_from_peer(p, path);
	BOOST_CHECK(ret == -1);
}

BOOST_FIXTURE_TEST_CASE(double_free_state, F)
{
	const char path[] = "/foo/bar/";
	cJSON *value = cJSON_CreateNumber(1234);
	cJSON *error = add_state_to_peer(p, path, value);
	BOOST_CHECK(error == NULL);

	cJSON_Delete(value);

	int ret = remove_state_from_peer(p, path);
	BOOST_CHECK(ret == 0);

	ret = remove_state_from_peer(p, path);
	BOOST_CHECK(ret == -1);
}

BOOST_FIXTURE_TEST_CASE(change, F)
{
	const char path[] = "/foo/bar/";
	cJSON *value = cJSON_CreateNumber(1234);
	cJSON *error = add_state_to_peer(p, path, value);
	BOOST_CHECK(error == NULL);
	cJSON_Delete(value);

	cJSON *new_value = cJSON_CreateNumber(4321);
	error = change_state(p, path, new_value);
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
	error = change_state(p, "/bar/foo/", new_value);
	BOOST_CHECK(error != NULL);
	cJSON_Delete(new_value);
	check_invalid_params(error);
	cJSON_Delete(error);
}

BOOST_FIXTURE_TEST_CASE(set, F)
{
	const char path[] = "/foo/bar/";
	cJSON *value = cJSON_CreateNumber(1234);
	cJSON *error = add_state_to_peer(p, path, value);
	BOOST_CHECK(error == NULL);
	cJSON_Delete(value);

	struct peer *set_peer = alloc_peer(-1);

	cJSON *set_request = cJSON_CreateObject();
	cJSON_AddStringToObject(set_request, "id", "request1");
	cJSON_AddStringToObject(set_request, "method", "set");

	cJSON *params = cJSON_CreateObject();
	cJSON_AddStringToObject(params, "path", "/foo/bar/");
	cJSON *new_value = cJSON_CreateNumber(4321);
	cJSON_AddItemToObject(params, "value", new_value);
	cJSON_AddItemToObject(set_request, "params", params);

	error = set_state(set_peer, path, new_value, set_request);
	cJSON_Delete(set_request);
	BOOST_CHECK(error == (cJSON *)ROUTED_MESSAGE);

	cJSON *routed_message = parse_send_buffer();
	cJSON *response = create_response_from_message(routed_message);
	cJSON *result = get_result_from_response(response);

	int ret = handle_routing_response(response, result, p);
	BOOST_CHECK(ret == 0);

	cJSON_Delete(routed_message);
	cJSON_Delete(response);

	free_peer(set_peer);
}

BOOST_FIXTURE_TEST_CASE(set_without_id_without_response, F)
{
	const char path[] = "/foo/bar/";
	cJSON *value = cJSON_CreateNumber(1234);
	cJSON *error = add_state_to_peer(p, path, value);
	BOOST_CHECK(error == NULL);
	cJSON_Delete(value);

	struct peer *set_peer = alloc_peer(-1);

	cJSON *set_request = cJSON_CreateObject();
	cJSON_AddStringToObject(set_request, "method", "set");

	cJSON *params = cJSON_CreateObject();
	cJSON_AddStringToObject(params, "path", "/foo/bar/");
	cJSON *new_value = cJSON_CreateNumber(4321);
	cJSON_AddItemToObject(params, "value", new_value);
	cJSON_AddItemToObject(set_request, "params", params);

	error = set_state(set_peer, path, new_value, set_request);
	cJSON_Delete(set_request);
	BOOST_CHECK(error == (cJSON *)ROUTED_MESSAGE);

	free_peer(set_peer);
}

BOOST_FIXTURE_TEST_CASE(set_without_id_with_response, F)
{
	const char path[] = "/foo/bar/";
	cJSON *value = cJSON_CreateNumber(1234);
	cJSON *error = add_state_to_peer(p, path, value);
	BOOST_CHECK(error == NULL);
	cJSON_Delete(value);

	struct peer *set_peer = alloc_peer(-1);

	cJSON *set_request = cJSON_CreateObject();
	cJSON_AddStringToObject(set_request, "method", "set");

	cJSON *params = cJSON_CreateObject();
	cJSON_AddStringToObject(params, "path", "/foo/bar/");
	cJSON *new_value = cJSON_CreateNumber(4321);
	cJSON_AddItemToObject(params, "value", new_value);
	cJSON_AddItemToObject(set_request, "params", params);

	error = set_state(set_peer, path, new_value, set_request);
	cJSON_Delete(set_request);
	BOOST_CHECK(error == (cJSON *)ROUTED_MESSAGE);

	cJSON *routed_message = parse_send_buffer();
	cJSON *response = create_response_from_message(routed_message);
	cJSON *result = get_result_from_response(response);

	int ret = handle_routing_response(response, result, p);
	BOOST_CHECK(ret == 0);

	cJSON_Delete(routed_message);
	cJSON_Delete(response);

	free_peer(set_peer);
}
