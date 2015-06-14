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

#include "json/cJSON.h"
#include "method.h"
#include "peer.h"
#include "router.h"
#include "state.h"

enum event {
	UNKNOWN_EVENT,
	ADD_EVENT,
	CHANGE_EVENT
};

static char send_buffer[100000];

static struct peer *fetch_peer_1;
static struct peer *fetch_peer_2;
static struct peer *set_peer;
static struct peer *call_peer;
static bool message_for_wrong_peer;

static enum event fetch_peer_1_event;
static enum event fetch_peer_2_event;

static cJSON *message_for_setter;

static cJSON *parse_send_buffer(void)
{
	const char *read_ptr = send_buffer;
	const char *end_parse;
	cJSON *root = cJSON_ParseWithOpts(read_ptr, &end_parse, 0);
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

extern "C" {
	int send_message(struct peer *p, const char *rendered, size_t len)
	{
		memcpy(send_buffer, rendered, len);
		if (p == fetch_peer_1) {
			cJSON *fetch_event = parse_send_buffer();
			fetch_peer_1_event = get_event_from_json(fetch_event);
			cJSON_Delete(fetch_event);
		} else if (p == fetch_peer_2) {
			cJSON *fetch_event = parse_send_buffer();
			fetch_peer_2_event = get_event_from_json(fetch_event);
			cJSON_Delete(fetch_event);
		} else if (p == set_peer) {
			message_for_setter = parse_send_buffer();
		} else {
			message_for_wrong_peer = true;
		}
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

struct F {
	F()
	{
		create_state_hashtable();
		create_method_hashtable();
		p = alloc_peer(-1);
		call_peer = alloc_peer(-1);
		fetch_peer_1 = alloc_peer(-1);
		fetch_peer_2 = alloc_peer(-1);
		set_peer = alloc_peer(-1);
		message_for_wrong_peer = false;
		message_for_setter = NULL;
	}
	~F()
	{
		if (set_peer) free_peer(set_peer);
		if (fetch_peer_2) free_peer(fetch_peer_2);
		if (fetch_peer_1) free_peer(fetch_peer_1);
		if (call_peer) free_peer(call_peer);
		if (p) free_peer(p);
		if (message_for_setter) cJSON_Delete(message_for_setter);
		delete_state_hashtable();
		delete_method_hashtable();
	}

	struct peer *p;
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

	cJSON *error = add_state_to_peer(p, path, value);
	BOOST_CHECK(error == NULL);

	cJSON_Delete(value);

	const struct state *s = get_state(path);
	BOOST_CHECK(s->value->valueint == state_value);

	struct fetch *f = NULL;
	cJSON *params = create_fetch_params(path);
	error = add_fetch_to_peer(fetch_peer_1, params, &f);
	BOOST_REQUIRE(error == NULL);
	int ret = add_fetch_to_states(f);
	BOOST_REQUIRE(ret == 0);
	error = add_fetch_to_peer(fetch_peer_2, params, &f);
	BOOST_REQUIRE(error == NULL);
	ret = add_fetch_to_states(f);
	BOOST_REQUIRE(ret == 0);

	BOOST_CHECK(fetch_peer_1_event == ADD_EVENT);
	BOOST_CHECK(fetch_peer_2_event == ADD_EVENT);

	cJSON *new_value = cJSON_CreateNumber(4321);
	error = change_state(p, path, new_value);
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
	cJSON *error = add_state_to_peer(p, path, value);
	BOOST_CHECK(error == NULL);
	cJSON_Delete(value);

	cJSON *set_request = create_set_request(path, "request1");
	cJSON *new_value = get_value_from_request(set_request);
	error = set_state(set_peer, path, new_value, set_request);
	cJSON_Delete(set_request);
	BOOST_CHECK(error == (cJSON *)ROUTED_MESSAGE);

	free_peer(p);
	p = NULL;

	error = cJSON_GetObjectItem(message_for_setter, "error");
	BOOST_REQUIRE(error != NULL);
	cJSON *code = cJSON_GetObjectItem(error, "code");
	BOOST_REQUIRE(code != NULL);
	BOOST_REQUIRE(code->type == cJSON_Number);
	BOOST_CHECK(code->valueint == -32603);
}

BOOST_FIXTURE_TEST_CASE(method_call_no_args, F)
{
	const char *path = "/foo/method/";

	cJSON *error = add_method_to_peer(call_peer, path);
	BOOST_CHECK(error == NULL);

	cJSON *call_json_rpc = create_call_json_rpc(path);
	error = call_method(p, path, NULL, call_json_rpc);
	BOOST_CHECK(error == (cJSON *)ROUTED_MESSAGE);
	cJSON_Delete(call_json_rpc);
}
