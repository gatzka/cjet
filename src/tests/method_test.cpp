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
#define BOOST_TEST_MODULE method

#include <boost/test/unit_test.hpp>

#include "json/cJSON.h"
#include "peer.h"
#include "router.h"
#include "state.h"
#include "table.h"

static const char *method_no_args_path = "/method_no_args/";

static const int INVALID_PARAMS_ERROR = -32602;

extern "C" {
	enum callback_return handle_all_peer_operations(union io_context *context)
	{
		(void)context;
		return CONTINUE_LOOP;
	}

	enum callback_return write_msg(union io_context *context)
	{
		(void)context;
		return CONTINUE_LOOP;
	}

	int send_message(struct peer *p, const char *rendered, size_t len)
	{
		(void)p;
		(void)rendered;
		(void)len;
		return 0;
	}

	enum callback_return eventloop_add_io(struct io_event *ev)
	{
		(void)ev;
		return CONTINUE_LOOP;
	}

	void eventloop_remove_io(struct io_event *ev)
	{
		(void)ev;
	}
}

struct F {
	F()
	{
		state_hashtable_create();
		owner_peer = alloc_peer(-1);
		call_peer = alloc_peer(-1);
	}
	~F()
	{
		free_peer(call_peer);
		free_peer(owner_peer);
		state_hashtable_delete();
	}

	struct peer *owner_peer;
	struct peer *call_peer;
};

static cJSON *create_call_json_rpc(const char *path_string)
{
	cJSON *root = cJSON_CreateObject();
	BOOST_REQUIRE(root != NULL);
	cJSON_AddStringToObject(root, "method", "call");
	cJSON_AddStringToObject(root, "id", "id_1");
	cJSON *params = cJSON_CreateObject();
	BOOST_REQUIRE(params != NULL);
	cJSON_AddItemToObject(root, "params", params);
	cJSON_AddStringToObject(params, "path", path_string);

	return root;
}

static cJSON *create_call_json_rpc_wrong_id_type(const char *path_string)
{
	cJSON *root = cJSON_CreateObject();
	BOOST_REQUIRE(root != NULL);
	cJSON_AddStringToObject(root, "method", "call");
	cJSON_AddTrueToObject(root, "id");
	cJSON *params = cJSON_CreateObject();
	BOOST_REQUIRE(params != NULL);
	cJSON_AddItemToObject(root, "params", params);
	cJSON_AddStringToObject(params, "path", path_string);

	return root;
}

static void check_invalid_params(const cJSON *error)
{
	cJSON *code = cJSON_GetObjectItem(error, "code");
	if (code != NULL) {
		BOOST_CHECK(code->type == cJSON_Number);
		BOOST_CHECK(code->valueint == INVALID_PARAMS_ERROR);
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

BOOST_FIXTURE_TEST_CASE(delete_nonexisting_state, F)
{
	const char path[] = "/foo/bar/";
	int ret = remove_state_or_method_from_peer(owner_peer, path);
	BOOST_CHECK(ret == -1);
}

BOOST_FIXTURE_TEST_CASE(call_wrong_path, F)
{

	cJSON *error = add_state_or_method_to_peer(owner_peer, "/foo/bar", NULL, 0x00);
	BOOST_CHECK(error == NULL);

	cJSON *call_json_rpc = create_call_json_rpc(method_no_args_path);
	error = set_or_call(owner_peer, "/bar/foo", NULL, call_json_rpc, METHOD);
	cJSON_Delete(call_json_rpc);

	if (error != NULL) {
		check_invalid_params(error);
		cJSON_Delete(error);
	} else {
		BOOST_FAIL("expected to get an error!");
	}
}

BOOST_FIXTURE_TEST_CASE(add_method_twice, F)
{
	const char path[] = "/foo/bar";

	cJSON *error = add_state_or_method_to_peer(owner_peer, path, NULL, 0x00);
	BOOST_CHECK(error == NULL);

	error = add_state_or_method_to_peer(owner_peer, path, NULL, 0x00);
	BOOST_REQUIRE(error != NULL);
	check_invalid_params(error);
	cJSON_Delete(error);
}

BOOST_FIXTURE_TEST_CASE(add_method_existing_state, F)
{
	const char path[] = "/foo/bar";
	int state_value = 12345;

	cJSON *value = cJSON_CreateNumber(state_value);
	cJSON *error = add_state_or_method_to_peer(owner_peer, path, value, 0x00);
	BOOST_CHECK(error == NULL);
	cJSON_Delete(value);

	error = add_state_or_method_to_peer(owner_peer, path, NULL, 0x00);
	BOOST_REQUIRE(error != NULL);
	check_invalid_params(error);
	cJSON_Delete(error);
}

BOOST_FIXTURE_TEST_CASE(call_on_state, F)
{
	const char path[] = "/foo/bar";
	int state_value = 12345;

	cJSON *value = cJSON_CreateNumber(state_value);
	cJSON *error = add_state_or_method_to_peer(owner_peer, path, value, 0x00);
	BOOST_CHECK(error == NULL);
	cJSON_Delete(value);

	cJSON *call_json_rpc = create_call_json_rpc(method_no_args_path);
	error = set_or_call(call_peer, path, NULL, call_json_rpc, METHOD);
	cJSON_Delete(call_json_rpc);

	if (error != NULL) {
		check_invalid_params(error);
		cJSON_Delete(error);
	} else {
		BOOST_FAIL("expected to get an error!");
	}
}

BOOST_FIXTURE_TEST_CASE(double_free_method, F)
{
	const char path[] = "/foo/bar";
	cJSON *error = add_state_or_method_to_peer(owner_peer, path, NULL, 0x00);
	BOOST_CHECK(error == NULL);

	int ret = remove_state_or_method_from_peer(owner_peer, path);
	BOOST_CHECK(ret == 0);

	ret = remove_state_or_method_from_peer(owner_peer, path);
	BOOST_CHECK(ret == -1);
}


BOOST_FIXTURE_TEST_CASE(correct_call, F)
{
	cJSON *error = add_state_or_method_to_peer(owner_peer, method_no_args_path, NULL, 0x00);
	BOOST_CHECK(error == NULL);

	cJSON *call_json_rpc = create_call_json_rpc(method_no_args_path);
	error = set_or_call(call_peer, method_no_args_path, NULL, call_json_rpc, METHOD);
	cJSON_Delete(call_json_rpc);
	BOOST_CHECK(error == (cJSON *)ROUTED_MESSAGE);
}

BOOST_FIXTURE_TEST_CASE(set_wrong_id_type, F)
{
	cJSON *error = add_state_or_method_to_peer(owner_peer, method_no_args_path, NULL, 0x00);
	BOOST_CHECK(error == NULL);

	cJSON *call_json_rpc = create_call_json_rpc_wrong_id_type(method_no_args_path);
	error = set_or_call(call_peer, method_no_args_path, NULL, call_json_rpc, METHOD);
	cJSON_Delete(call_json_rpc);

	if ((error != NULL) && (error != (cJSON *)ROUTED_MESSAGE)) {
		check_invalid_params(error);
		cJSON_Delete(error);
	} else  {
		BOOST_FAIL("expected to get an error!");
	}
}
