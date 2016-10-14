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
#define BOOST_TEST_MODULE combined

#include <boost/test/unit_test.hpp>

#include "eventloop.h"
#include "json/cJSON.h"
#include "parse.h"
#include "peer.h"
#include "router.h"
#include "state.h"
#include "table.h"

enum event {
	UNKNOWN_EVENT,
	ADD_EVENT,
	CHANGE_EVENT
};

enum result {
	UNKNOWN,
	SUCCESS,
	ERROR
};

static const int READ_ONLY_SET_ERROR = -1;
static const char *method_no_args_path = "/method_no_args/";
static const char *read_only_state_path = "read_only_state";

static const int JSON_RPC_INTERNAL_ERROR = -32603;

static struct peer *owner_peer;
static struct peer *fetch_peer_1;
static struct peer *fetch_peer_2;
static struct peer *set_peer;
static struct peer *call_peer;
static bool message_for_wrong_peer;

static int setter_caller_error_code;
static enum result setter_caller_result;

static enum event fetch_peer_1_event;
static enum event fetch_peer_2_event;

static cJSON *parse_send_buffer(const char *buffer)
{
	const char *end_parse;
	cJSON *root = cJSON_ParseWithOpts(buffer, &end_parse, 0);
	return root;
}

static enum event get_event_from_json(cJSON *json)
{
	const cJSON *params = cJSON_GetObjectItem(json, "params");
	if (params == NULL) return UNKNOWN_EVENT;
	const cJSON *event = cJSON_GetObjectItem(params, "event");
	if (event == NULL) return UNKNOWN_EVENT;
	if (event->type != cJSON_String) return UNKNOWN_EVENT;
	if (strcmp(event->valuestring, "add") == 0) return ADD_EVENT;
	if (strcmp(event->valuestring, "change") == 0) return CHANGE_EVENT;
	return UNKNOWN_EVENT;
}

static cJSON *create_no_args_response(const cJSON *routed_message)
{
	const cJSON *id = cJSON_GetObjectItem(routed_message, "id");
	cJSON *duplicated_id = cJSON_Duplicate(id, 1);

	cJSON *response = cJSON_CreateObject();
	cJSON_AddItemToObject(response, "id", duplicated_id);
	cJSON *result = cJSON_CreateString("o.k.");
	cJSON_AddItemToObject(response, "result", result);
	return response;
}

static cJSON *create_error_response(const cJSON *routed_message)
{
	const cJSON *id = cJSON_GetObjectItem(routed_message, "id");
	cJSON *duplicated_id = cJSON_Duplicate(id, 1);

	cJSON *response = cJSON_CreateObject();
	cJSON_AddItemToObject(response, "id", duplicated_id);
	cJSON *error = cJSON_CreateObject();
	cJSON_AddNumberToObject(error, "code", READ_ONLY_SET_ERROR);
	cJSON_AddStringToObject(error, "message", "Manipulating read-only string");
	cJSON_AddItemToObject(response, "error", error);
	return response;
}

static cJSON *get_result_from_response(const cJSON *response)
{
	cJSON *result = cJSON_GetObjectItem(response, "result");
	if (result != NULL) {
		return result;
	}
	cJSON *error = cJSON_GetObjectItem(response, "error");
	if (error != NULL) {
		return error;
	}
	return NULL;
}

static void create_and_send_owner_response(const char *rendered)
{
	cJSON *message_for_owner = parse_send_buffer(rendered);
	cJSON *method = cJSON_GetObjectItem(message_for_owner, "method");
	if (method != NULL) {
		BOOST_REQUIRE(method->type == cJSON_String);
		if (::strcmp(method->valuestring, method_no_args_path) == 0) {
			cJSON *response = create_no_args_response(message_for_owner);
			cJSON *result = get_result_from_response(response);
			int ret = handle_routing_response(response, result, "result", owner_peer);
			BOOST_CHECK(ret == 0);
			cJSON_Delete(response);
		} else if (::strcmp(method->valuestring, read_only_state_path) == 0) {
			cJSON *response = create_error_response(message_for_owner);
			cJSON *result = get_result_from_response(response);
			int ret = handle_routing_response(response, result, "error", owner_peer);
			BOOST_CHECK(ret == 0);
			cJSON_Delete(response);
		}
	} else {
		BOOST_FAIL("No method in object!");
	}

	cJSON_Delete(message_for_owner);
}

static void handle_message_for_setter_or_caller(const char *rendered)
{
	cJSON *message = parse_send_buffer(rendered);

	cJSON *result = cJSON_GetObjectItem(message, "result");
	if (result != NULL) {
		setter_caller_result = SUCCESS;
	} else {
		cJSON *error = cJSON_GetObjectItem(message, "error");
		if (error != NULL) {
			cJSON *code = cJSON_GetObjectItem(error, "code");
			BOOST_REQUIRE(code != NULL);
			if (code != NULL) {
				BOOST_REQUIRE(code->type == cJSON_Number);
				setter_caller_error_code = code->valueint;
				setter_caller_result = ERROR;
			} else {
				BOOST_FAIL("No code object in error!");
			}
		} else {
			BOOST_FAIL("Unknown message for setter!");
		}
	}
	cJSON_Delete(message);
}

static struct state_or_method *get_state(const char *path)
{
	return (struct state_or_method *)state_table_get(path);
}

int send_message(const struct peer *p, char *rendered, size_t len)
{
	(void)len;
	if (p == fetch_peer_1) {
		cJSON *fetch_event = parse_send_buffer(rendered);
		fetch_peer_1_event = get_event_from_json(fetch_event);
		cJSON_Delete(fetch_event);
	} else if (p == fetch_peer_2) {
		cJSON *fetch_event = parse_send_buffer(rendered);
		fetch_peer_2_event = get_event_from_json(fetch_event);
		cJSON_Delete(fetch_event);
	} else if ((p == set_peer) || (p == call_peer)) {
		handle_message_for_setter_or_caller(rendered);
	} else if (p == owner_peer) {
		create_and_send_owner_response(rendered);
	} else {
		message_for_wrong_peer = true;
	}
	return 0;
}

static enum eventloop_return fake_add(const void *this_ptr, const struct io_event *ev)
{
	(void)this_ptr;
	(void)ev;
	return EL_CONTINUE_LOOP;
}

static void fake_remove(const void *this_ptr, const struct io_event *ev)
{
	(void)this_ptr;
	(void)ev;
	return;
}

static struct eventloop loop;

struct peer *alloc_peer()
{
	struct peer *p = (struct peer *)::malloc(sizeof(*p));
	init_peer(p, false, &loop);
	p->send_message = send_message;
	return p;
}

void free_peer(struct peer *p)
{
	free_peer_resources(p);
	::free(p);
}

struct F {
	F()
	{
		loop.this_ptr = NULL;
		loop.init = NULL;
		loop.destroy = NULL;
		loop.run = NULL;
		loop.add = fake_add;
		loop.remove = fake_remove;

		init_parser();
		state_hashtable_create();
		owner_peer = alloc_peer();
		call_peer = alloc_peer();
		fetch_peer_1 = alloc_peer();
		fetch_peer_2 = alloc_peer();
		set_peer = alloc_peer();
		message_for_wrong_peer = false;
		setter_caller_error_code = 0;
		setter_caller_result = UNKNOWN;
	}
	~F()
	{
		if (set_peer) free_peer(set_peer);
		if (fetch_peer_2) free_peer(fetch_peer_2);
		if (fetch_peer_1) free_peer( fetch_peer_1);
		if (call_peer) free_peer( call_peer);
		if (owner_peer) free_peer(owner_peer);
		state_hashtable_delete();
	}
};

static cJSON *create_fetch_params(const char *path_string)
{
	cJSON *root = cJSON_CreateObject();
	BOOST_REQUIRE(root != NULL);
	cJSON_AddStringToObject(root, "id", "fetch_id_1");
	cJSON *path = cJSON_CreateObject();
	BOOST_REQUIRE(path != NULL);
	cJSON_AddItemToObject(root, "path", path);
	cJSON_AddStringToObject(path, "equals", path_string);

	return root;
}

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

static cJSON *create_set_request(const char *path, const char *request_id)
{
	cJSON *set_request = cJSON_CreateObject();
	cJSON_AddStringToObject(set_request, "method", "set");
	if (request_id != NULL) {
		cJSON_AddStringToObject(set_request, "id", request_id);
	}

	cJSON *params = cJSON_CreateObject();
	cJSON_AddStringToObject(params, "path", path);
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

BOOST_FIXTURE_TEST_CASE(two_fetch_and_change, F)
{
	const char *path = "/foo/bar/";
	int state_value = 12345;
	cJSON *value = cJSON_CreateNumber(state_value);

	cJSON *error = add_state_or_method_to_peer(owner_peer, path, value, 0x00);
	BOOST_CHECK(error == NULL);

	cJSON_Delete(value);

	const struct state_or_method *s = get_state(path);
	BOOST_CHECK(s->value->valueint == state_value);

	struct fetch *f = NULL;
	cJSON *params = create_fetch_params(path);
	error = add_fetch_to_peer(fetch_peer_1, params, &f);
	BOOST_REQUIRE(error == NULL);
	error = add_fetch_to_states(f);
	BOOST_REQUIRE(error == NULL);
	error = add_fetch_to_peer(fetch_peer_2, params, &f);
	BOOST_REQUIRE(error == NULL);
	error = add_fetch_to_states(f);
	BOOST_REQUIRE(error == NULL);

	BOOST_CHECK(fetch_peer_1_event == ADD_EVENT);
	BOOST_CHECK(fetch_peer_2_event == ADD_EVENT);

	cJSON *new_value = cJSON_CreateNumber(4321);
	error = change_state(owner_peer, path, new_value);
	BOOST_REQUIRE(error == NULL);
	cJSON_Delete(new_value);

	BOOST_CHECK(fetch_peer_1_event == CHANGE_EVENT);
	BOOST_CHECK(fetch_peer_2_event == CHANGE_EVENT);

	BOOST_CHECK(!message_for_wrong_peer);
	remove_all_fetchers_from_peer(fetch_peer_1);
	remove_all_fetchers_from_peer(fetch_peer_2);
	cJSON_Delete(params);
}

BOOST_FIXTURE_TEST_CASE(owner_shutdown_before_set_response, F)
{
	const char *path = "/foo/bar/";
	int state_value = 12345;
	cJSON *value = cJSON_CreateNumber(state_value);
	cJSON *error = add_state_or_method_to_peer(owner_peer, path, value, 0x00);
	BOOST_CHECK(error == NULL);
	cJSON_Delete(value);

	cJSON *set_request = create_set_request(path, "request1");
	cJSON *new_value = get_value_from_request(set_request);
	error = set_or_call(set_peer, path, new_value, set_request, STATE);
	cJSON_Delete(set_request);
	BOOST_CHECK(error == (cJSON *)ROUTED_MESSAGE);

	free_peer(owner_peer);
	owner_peer = NULL;

	BOOST_CHECK(setter_caller_result == ERROR);
	BOOST_CHECK(setter_caller_error_code == JSON_RPC_INTERNAL_ERROR);
}

BOOST_FIXTURE_TEST_CASE(method_call_no_args, F)
{
	cJSON *error = add_state_or_method_to_peer(owner_peer, method_no_args_path, NULL, 0x00);
	BOOST_CHECK(error == NULL);

	cJSON *call_json_rpc = create_call_json_rpc(method_no_args_path);
	error = set_or_call(call_peer, method_no_args_path, NULL, call_json_rpc, METHOD);
	BOOST_CHECK(error == (cJSON *)ROUTED_MESSAGE);
	cJSON_Delete(call_json_rpc);

	BOOST_CHECK(setter_caller_result == SUCCESS);
}

BOOST_FIXTURE_TEST_CASE(set_with_error, F)
{
	int state_value = 12345;
	cJSON *value = cJSON_CreateNumber(state_value);
	cJSON *error = add_state_or_method_to_peer(owner_peer, read_only_state_path, value, 0x00);
	BOOST_CHECK(error == NULL);
	cJSON_Delete(value);

	cJSON *set_request = create_set_request(read_only_state_path, "request1");
	cJSON *new_value = get_value_from_request(set_request);
	error = set_or_call(set_peer, read_only_state_path, new_value, set_request, STATE);
	cJSON_Delete(set_request);
	BOOST_CHECK(error == (cJSON *)ROUTED_MESSAGE);

	BOOST_CHECK(setter_caller_result == ERROR);
	BOOST_CHECK(setter_caller_error_code == READ_ONLY_SET_ERROR);
}
