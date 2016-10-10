/*
 * The MIT License (MIT)
 *
 * Copyright (c) <2015> <Stephan Gatzka>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MAIN
#define BOOST_TEST_MODULE state

#include <boost/test/unit_test.hpp>

#include "json/cJSON.h"
#include "parse.h"
#include "peer.h"
#include "router.h"
#include "state.h"
#include "table.h"

static char send_buffer[100000];

int send_message(const struct peer *p, char *rendered, size_t len)
{
	(void)p;
	memcpy(send_buffer, rendered, len);
	return 0;
}
static struct state_or_method *get_state(const char *path)
{
	return (struct state_or_method *)state_table_get(path);
}

static cJSON *parse_send_buffer(void)
{
	char *read_ptr = send_buffer;
	const char *end_parse;
	cJSON *root = cJSON_ParseWithOpts(read_ptr, &end_parse, 0);
	return root;
}

static cJSON *create_response_from_message(const cJSON *routed_message)
{
	const cJSON *id = cJSON_GetObjectItem(routed_message, "id");
	cJSON *duplicated_id = cJSON_Duplicate(id, 1);

	cJSON *response = cJSON_CreateObject();
	cJSON_AddItemToObject(response, "id", duplicated_id);
	cJSON *result = cJSON_CreateString("");
	cJSON_AddItemToObject(response, "result", result);
	return response;
}

static cJSON *create_set_request(const char *request_id)
{
	cJSON *set_request = cJSON_CreateObject();
	cJSON_AddStringToObject(set_request, "method", "set");
	if (request_id != NULL) {
		cJSON_AddStringToObject(set_request, "id", request_id);
	}

	cJSON *params = cJSON_CreateObject();
	cJSON_AddStringToObject(params, "path", "/foo/bar/");
	cJSON *new_value = cJSON_CreateNumber(4321);
	cJSON_AddItemToObject(params, "value", new_value);
	cJSON_AddItemToObject(set_request, "params", params);
	return set_request;
}

static cJSON *get_value_from_request(const cJSON *set_request)
{
	cJSON *params = cJSON_GetObjectItem(set_request, "params");
	cJSON *value = cJSON_GetObjectItem(params, "value");
	return value;
}

static cJSON *get_result_from_response(const cJSON *response)
{
	cJSON *result = cJSON_GetObjectItem(response, "result");
	if (result != NULL) {
		return result;
	}
	const cJSON *error = cJSON_GetObjectItem(response, "error");
	if (error != NULL) {
		return result;
	}
	return NULL;
}

struct F {
	F()
	{
		init_parser();
		state_hashtable_create();
		init_peer(&p, false, NULL);
		p.send_message = send_message;
		init_peer(&owner_peer, false, NULL);
		owner_peer.send_message = send_message;
		init_peer(&set_peer, false, NULL);
		set_peer.send_message = send_message;
	}
	~F()
	{
		free_peer_resources(&set_peer);
		free_peer_resources(&owner_peer);
		free_peer_resources(&p);
		state_hashtable_delete();
	}

	struct peer p;
	struct peer owner_peer;
	struct peer set_peer;
};

static void check_invalid_params(const cJSON *error)
{
	cJSON *code = cJSON_GetObjectItem(error, "code");
	if (code != NULL) {
		BOOST_CHECK(code->type == cJSON_Number);
		BOOST_CHECK(code->valueint == -32602);
	} else {
		BOOST_FAIL("No code object!");
	}

	cJSON *message = cJSON_GetObjectItem(error, "message");
	if (message != NULL) {
		BOOST_CHECK(message->type == cJSON_String);
		BOOST_CHECK(strcmp(message->valuestring, "Invalid params") == 0);
	} else {
		BOOST_FAIL("No message object!");
	}
}

BOOST_FIXTURE_TEST_CASE(add_state_existing_method, F)
{
	const char path[] = "/foo/bar";
	int state_value = 12345;

	cJSON *error = add_state_or_method_to_peer(&owner_peer, path, NULL, 0x00);
	BOOST_CHECK(error == NULL);

	cJSON *value = cJSON_CreateNumber(state_value);
	error = add_state_or_method_to_peer(&owner_peer, path, value, 0x00);
	cJSON_Delete(value);
	BOOST_REQUIRE(error != NULL);
	check_invalid_params(error);
	cJSON_Delete(error);
}

BOOST_FIXTURE_TEST_CASE(add_state, F)
{
	const char *path = "/foo/bar/";
	int state_value = 12345;
	cJSON *value = cJSON_CreateNumber(state_value);

	cJSON *error = add_state_or_method_to_peer(&p, path, value, 0x00);
	BOOST_CHECK(error == NULL);

	cJSON_Delete(value);

	struct state_or_method *s = get_state(path);
	BOOST_CHECK(s->value->valueint == state_value);
}

BOOST_FIXTURE_TEST_CASE(add_duplicate_state, F)
{
	cJSON *value = cJSON_CreateNumber(1234);

	cJSON *error = add_state_or_method_to_peer(&p, "/foo/bar/", value, 0x00);
	BOOST_CHECK(error == NULL);

	error = add_state_or_method_to_peer(&p, "/foo/bar/", value, 0x00);
	BOOST_REQUIRE(error != NULL);
	check_invalid_params(error);
	cJSON_Delete(error);
	cJSON_Delete(value);
}

BOOST_FIXTURE_TEST_CASE(delete_single_state, F)
{
	const char path[] = "/foo/bar/";
	cJSON *value = cJSON_CreateNumber(1234);
	cJSON *error = add_state_or_method_to_peer(&p, path, value, 0x00);
	BOOST_CHECK(error == NULL);

	cJSON_Delete(value);

	int ret = remove_state_or_method_from_peer(&p, path);
	BOOST_CHECK(ret == 0);
}

BOOST_FIXTURE_TEST_CASE(delete_nonexisting_state, F)
{
	const char path[] = "/foo/bar/";
	int ret = remove_state_or_method_from_peer(&p, path);
	BOOST_CHECK(ret == -1);
}

BOOST_FIXTURE_TEST_CASE(double_free_state, F)
{
	const char path[] = "/foo/bar/";
	cJSON *value = cJSON_CreateNumber(1234);
	cJSON *error = add_state_or_method_to_peer(&p, path, value, 0x00);
	BOOST_CHECK(error == NULL);

	cJSON_Delete(value);

	int ret = remove_state_or_method_from_peer(&p, path);
	BOOST_CHECK(ret == 0);

	ret = remove_state_or_method_from_peer(&p, path);
	BOOST_CHECK(ret == -1);
}

BOOST_FIXTURE_TEST_CASE(change, F)
{
	const char path[] = "/foo/bar/";
	cJSON *value = cJSON_CreateNumber(1234);
	cJSON *error = add_state_or_method_to_peer(&p, path, value, 0x00);
	BOOST_CHECK(error == NULL);
	cJSON_Delete(value);

	cJSON *new_value = cJSON_CreateNumber(4321);
	error = change_state(&p, path, new_value);
	BOOST_CHECK(error == NULL);
	cJSON_Delete(new_value);

	struct state_or_method *s = get_state(path);
	BOOST_CHECK(s->value->valueint == 4321);
}

BOOST_FIXTURE_TEST_CASE(change_not_by_owner, F)
{
	const char path[] = "/foo/bar/";
	cJSON *value = cJSON_CreateNumber(1234);
	cJSON *error = add_state_or_method_to_peer(&p, path, value, 0x00);
	BOOST_CHECK(error == NULL);
	cJSON_Delete(value);

	cJSON *new_value = cJSON_CreateNumber(4321);
	error = change_state(&set_peer, path, new_value);
	BOOST_CHECK(error != NULL);
	cJSON_Delete(new_value);
	cJSON_Delete(error);
}

BOOST_FIXTURE_TEST_CASE(change_wrong_path, F)
{
	cJSON *value = cJSON_CreateNumber(1234);
	cJSON *error = add_state_or_method_to_peer(&p, "/foo/bar/", value, 0x00);
	BOOST_CHECK(error == NULL);
	cJSON_Delete(value);

	cJSON *new_value = cJSON_CreateNumber(4321);
	error = change_state(&p, "/bar/foo/", new_value);
	BOOST_CHECK(error != NULL);
	cJSON_Delete(new_value);
	check_invalid_params(error);
	cJSON_Delete(error);
}

BOOST_FIXTURE_TEST_CASE(change_on_method, F)
{
	const char path[] = "/foo/bar";
	cJSON *error = add_state_or_method_to_peer(&p, path, NULL, 0x00);
	BOOST_CHECK(error == NULL);

	cJSON *value = cJSON_CreateNumber(1234);
	error = change_state(&p, path, value);
	BOOST_REQUIRE(error != NULL);
	cJSON_Delete(value);
	check_invalid_params(error);
	cJSON_Delete(error);
}

BOOST_FIXTURE_TEST_CASE(set_on_method, F)
{
	const char path[] = "/foo/bar";
	cJSON *error = add_state_or_method_to_peer(&p, path, NULL, 0x00);
	BOOST_CHECK(error == NULL);

	cJSON *set_request = create_set_request("request1");
	cJSON *new_value = get_value_from_request(set_request);
	error = set_or_call(&set_peer, path, new_value, set_request, STATE);
	cJSON_Delete(set_request);
	BOOST_REQUIRE(error != NULL);
	check_invalid_params(error);
	cJSON_Delete(error);
}

BOOST_FIXTURE_TEST_CASE(set_on_fetchonly, F)
{
	const char path[] = "/foo/bar";
	cJSON *error = add_state_or_method_to_peer(&p, path, NULL, FETCH_ONLY_FLAG);
	BOOST_CHECK(error == NULL);

	cJSON *set_request = create_set_request("request1");
	cJSON *new_value = get_value_from_request(set_request);
	error = set_or_call(&set_peer, path, new_value, set_request, STATE);
	cJSON_Delete(set_request);
	BOOST_REQUIRE(error != NULL);
	check_invalid_params(error);
	cJSON_Delete(error);
}

BOOST_FIXTURE_TEST_CASE(set, F)
{
	const char path[] = "/foo/bar/";
	cJSON *value = cJSON_CreateNumber(1234);
	cJSON *error = add_state_or_method_to_peer(&p, path, value, 0x00);
	BOOST_CHECK(error == NULL);
	cJSON_Delete(value);

	cJSON *set_request = create_set_request("request1");
	cJSON *new_value = get_value_from_request(set_request);
	error = set_or_call(&set_peer, path, new_value, set_request, STATE);
	cJSON_Delete(set_request);
	BOOST_CHECK(error == (cJSON *)ROUTED_MESSAGE);

	cJSON *routed_message = parse_send_buffer();
	cJSON *response = create_response_from_message(routed_message);
	cJSON *result = get_result_from_response(response);

	int ret = handle_routing_response(response, result, "result", &p);
	BOOST_CHECK(ret == 0);

	cJSON_Delete(routed_message);
	cJSON_Delete(response);
}

BOOST_FIXTURE_TEST_CASE(set_wrong_path, F)
{
	cJSON *value = cJSON_CreateNumber(1234);
	cJSON *error = add_state_or_method_to_peer(&p, "/foo/bar/bla/", value, 0x00);
	BOOST_CHECK(error == NULL);
	cJSON_Delete(value);

	cJSON *set_request = create_set_request("request1");
	cJSON *new_value = get_value_from_request(set_request);
	error = set_or_call(&set_peer, "/foo/bar/", new_value, set_request, STATE);
	cJSON_Delete(set_request);
	BOOST_CHECK(error != NULL && error != (cJSON *)ROUTED_MESSAGE);

	cJSON_Delete(error);
}

BOOST_FIXTURE_TEST_CASE(set_without_id_without_response, F)
{
	const char path[] = "/foo/bar/";
	cJSON *value = cJSON_CreateNumber(1234);
	cJSON *error = add_state_or_method_to_peer(&p, path, value, 0x00);
	BOOST_CHECK(error == NULL);
	cJSON_Delete(value);

	cJSON *set_request = create_set_request(NULL);
	cJSON *new_value = get_value_from_request(set_request);

	error = set_or_call(&set_peer, path, new_value, set_request, STATE);
	cJSON_Delete(set_request);
	BOOST_CHECK(error == (cJSON *)ROUTED_MESSAGE);
}

BOOST_FIXTURE_TEST_CASE(set_wrong_id_type, F)
{
	const char path[] = "/foo/bar/";
	cJSON *value = cJSON_CreateNumber(1234);
	cJSON *error = add_state_or_method_to_peer(&p, path, value, 0x00);
	BOOST_CHECK(error == NULL);
	cJSON_Delete(value);

	cJSON *set_request = cJSON_CreateObject();
	cJSON_AddStringToObject(set_request, "method", "set");
	cJSON_AddTrueToObject(set_request, "id");

	cJSON *params = cJSON_CreateObject();
	cJSON_AddStringToObject(params, "path", "/foo/bar/");
	cJSON *new_value = cJSON_CreateNumber(4321);
	cJSON_AddItemToObject(params, "value", new_value);
	cJSON_AddItemToObject(set_request, "params", params);

	error = set_or_call(&set_peer, path, new_value, set_request, STATE);
	cJSON_Delete(set_request);

	BOOST_CHECK(error != NULL && error != (cJSON *)ROUTED_MESSAGE);
	cJSON_Delete(error);
}

BOOST_FIXTURE_TEST_CASE(set_without_id_with_response, F)
{
	const char path[] = "/foo/bar/";
	cJSON *value = cJSON_CreateNumber(1234);
	cJSON *error = add_state_or_method_to_peer(&p, path, value, 0x00);
	BOOST_CHECK(error == NULL);
	cJSON_Delete(value);

	cJSON *set_request = create_set_request(NULL);
	cJSON *new_value = get_value_from_request(set_request);
	error = set_or_call(&set_peer, path, new_value, set_request, STATE);
	cJSON_Delete(set_request);
	BOOST_CHECK(error == (cJSON *)ROUTED_MESSAGE);

	cJSON *routed_message = parse_send_buffer();
	cJSON *response = create_response_from_message(routed_message);
	cJSON *result = get_result_from_response(response);

	int ret = handle_routing_response(response, result, "result", &p);
	BOOST_CHECK(ret == 0);

	cJSON_Delete(routed_message);
	cJSON_Delete(response);
}
