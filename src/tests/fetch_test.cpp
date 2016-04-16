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
#define BOOST_TEST_MODULE fetch

#include <boost/test/unit_test.hpp>
#include <list>

#include "json/cJSON.h"
#include "parse.h"
#include "peer.h"
#include "router.h"
#include "state.h"
#include "table.h"

enum event {
	UNKNOWN_EVENT,
	ADD_EVENT,
	CHANGE_EVENT,
	REMOVE_EVENT
};

static struct peer *fetch_peer_1;
static struct peer *set_peer;
static struct peer *owner_peer;

static std::list<cJSON*> fetch_events;
static std::list<cJSON*> owner_responses;

static cJSON *parse_send_buffer(const char *json)
{
	const char *end_parse;
	cJSON *root = cJSON_ParseWithOpts(json, &end_parse, 0);
	return root;
}

static enum event get_event_from_json(cJSON *json)
{
	cJSON *params = cJSON_GetObjectItem(json, "params");
	if (params == NULL) return UNKNOWN_EVENT;
	cJSON *event = cJSON_GetObjectItem(params, "event");
	if (event == NULL) return UNKNOWN_EVENT;
	if (event->type != cJSON_String) return UNKNOWN_EVENT;
	if (strcmp(event->valuestring, "add") == 0) return ADD_EVENT;
	if (strcmp(event->valuestring, "change") == 0) return CHANGE_EVENT;
	if (strcmp(event->valuestring, "remove") == 0) return REMOVE_EVENT;
	return UNKNOWN_EVENT;
}

static cJSON *create_correct_add_state(const char *path, int id, int value)
{
	cJSON *root = cJSON_CreateObject();
	BOOST_REQUIRE(root != NULL);
	cJSON_AddNumberToObject(root, "id", id);
	cJSON_AddStringToObject(root, "method", "add");

	cJSON *params = cJSON_CreateObject();
	BOOST_REQUIRE(params != NULL);
	cJSON_AddStringToObject(params, "path", path);
	cJSON_AddNumberToObject(params, "value", value);
	cJSON_AddItemToObject(root, "params", params);
	return root;
}

static cJSON *create_correct_set_method(const char *path, int value)
{
	cJSON *root = cJSON_CreateObject();
	BOOST_REQUIRE(root != NULL);
	cJSON_AddNumberToObject(root, "id", 9999);
	cJSON_AddStringToObject(root, "method", "set");

	cJSON *params = cJSON_CreateObject();
	BOOST_REQUIRE(params != NULL);
	cJSON_AddStringToObject(params, "path", path);
	cJSON_AddNumberToObject(params, "value", value);
	cJSON_AddItemToObject(root, "params", params);
	return root;
}

static cJSON *create_correct_fetch(const char *path, int id)
{
	cJSON *root = cJSON_CreateObject();
	BOOST_REQUIRE(root != NULL);
	cJSON_AddNumberToObject(root, "id", id);
	cJSON_AddStringToObject(root, "method", "fetch");

	cJSON *params = cJSON_CreateObject();
	BOOST_REQUIRE(params != NULL);

	cJSON *json_path = cJSON_CreateObject();
	BOOST_REQUIRE(json_path != NULL);
	cJSON_AddStringToObject(json_path, "startsWith", path);

	cJSON_AddItemToObject(params, "path", json_path);
	cJSON_AddStringToObject(params, "id", "fetch_id_1");
	cJSON_AddItemToObject(root, "params", params);
	return root;
}

static void check_response(cJSON *json, int id)
{
	cJSON *response_id = cJSON_GetObjectItem(json, "id");
	BOOST_CHECK((response_id != NULL) &&
	             (response_id->type == cJSON_Number) &&
				 (response_id->valueint == id));
	cJSON *result = cJSON_GetObjectItem(json, "result");
	BOOST_CHECK(result != NULL);
}

static char *get_routed_id(const cJSON *json)
{
	cJSON *id = cJSON_GetObjectItem(json, "id");
	BOOST_REQUIRE(id != NULL);
	BOOST_REQUIRE(id->type == cJSON_String);
	return strdup(id->valuestring);
}

static cJSON *create_result_json(const char *id)
{
	cJSON *root = cJSON_CreateObject();
	BOOST_REQUIRE(root != NULL);
	cJSON_AddStringToObject(root, "id", id);
	cJSON *result = cJSON_CreateTrue();
	BOOST_REQUIRE(result != NULL);
	cJSON_AddItemToObject(root, "result", result);
	return root;
}

static void check_no_error(int id)
{
	cJSON *response = owner_responses.front();
	owner_responses.pop_front();
	BOOST_REQUIRE(response != NULL);

	const cJSON *error = cJSON_GetObjectItem(response, "error");
	BOOST_CHECK(error == NULL);
	const cJSON *json_id = cJSON_GetObjectItem(response, "id");
	BOOST_REQUIRE(json_id != NULL);
	BOOST_REQUIRE(json_id->type == cJSON_Number);
	BOOST_CHECK(json_id->valueint == id);
	cJSON_Delete(response);
}

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
		(void)len;
		if (p == fetch_peer_1) {
			cJSON *fetch_event = parse_send_buffer(rendered);
			fetch_events.push_back(fetch_event);
		} else if (p == owner_peer) {
			cJSON *response = parse_send_buffer(rendered);
			owner_responses.push_back(response);
		}
		return 0;
	}

	int add_io(struct peer *p)
	{
		(void)p;
		return 0;
	}

	void remove_io(const struct peer *p)
	{
		(void)p;
		return;
	}

	void remove_all_methods_from_peer(struct peer *p)
	{
		(void)p;
	}
}

struct F {
	F()
	{
		state_hashtable_create();
		owner_peer = alloc_peer(-1);
		set_peer = alloc_peer(-1);
		fetch_peer_1 = alloc_peer(-1);
	}

	~F()
	{
		while (!fetch_events.empty()) {
			cJSON *ptr = fetch_events.front();
			fetch_events.pop_front();
			cJSON_Delete(ptr);
		}
		while (!owner_responses.empty()) {
			cJSON *ptr = owner_responses.front();
			owner_responses.pop_front();
			cJSON_Delete(ptr);
		}
		free_peer(fetch_peer_1);
		free_peer(set_peer);
		free_peer(owner_peer);
		state_hashtable_delete();
	}
};

static struct state_or_method *get_state(const char *path)
{
	return (struct state_or_method *)state_table_get(path);
}

static cJSON *create_fetch_params(const char *path_equals_string, const char *path_startsWith_string, const char *path_endsWith_string, const char *path_contains, int ignore_case)
{
	cJSON *root = cJSON_CreateObject();
	BOOST_REQUIRE(root != NULL);
	cJSON_AddStringToObject(root, "id", "fetch_id_1");
	cJSON *path = cJSON_CreateObject();
	BOOST_REQUIRE(path != NULL);
	cJSON_AddItemToObject(root, "path", path);
	if (strlen(path_equals_string)) {
		cJSON_AddStringToObject(path, "equals", path_equals_string);
	}

	if (strlen(path_startsWith_string)) {
		cJSON_AddStringToObject(path, "startsWith", path_startsWith_string);
	}

	if (strlen(path_endsWith_string)) {
		cJSON_AddStringToObject(path, "endsWith", path_endsWith_string);
	}

	if (strlen(path_contains)) {
		cJSON_AddStringToObject(path, "contains", path_contains);
	}

	if (ignore_case) {
		cJSON_AddBoolToObject(root, "caseInsensitive", 1);
	}

	return root;
}

static cJSON *create_unfetch_params()
{
	cJSON *root = cJSON_CreateObject();
	BOOST_REQUIRE(root != NULL);
	cJSON_AddStringToObject(root, "id", "fetch_id_1");

	return root;
}

BOOST_FIXTURE_TEST_CASE(fetch_matchers, F)
{
	const char *path = "foo/bar";
	const char *path_upper = "FOO/BAR";
	const char *path_startsWith = "foo";
	const char *path_endsWith = "bar";
	const char *path_contains = "oo/ba";

	int state_value = 12345;

	{
		cJSON *value = cJSON_CreateNumber(state_value);

		cJSON *error = add_state_or_method_to_peer(owner_peer, path, value, 0x00);
		BOOST_CHECK(error == NULL);

		cJSON_Delete(value);
	}

	struct state_or_method *s = get_state(path);
	BOOST_CHECK(s->value->valueint == state_value);
	{
		/// is to fail because fetch is case sensitive
		struct fetch *f = NULL;
		cJSON *params = create_fetch_params(path_upper, "", "", "", 0);
		cJSON *error = add_fetch_to_peer(fetch_peer_1, params, &f);
		BOOST_REQUIRE(error == NULL);
		error = add_fetch_to_states(f);
		BOOST_REQUIRE(error == NULL);

		BOOST_CHECK(fetch_events.size() == 0);
		remove_all_fetchers_from_peer(fetch_peer_1);
		cJSON_Delete(params);
	}

	{
		struct fetch *f = NULL;
		cJSON *params = create_fetch_params(path, "", "", "", 0);
		cJSON *error = add_fetch_to_peer(fetch_peer_1, params, &f);
		BOOST_REQUIRE(error == NULL);
		error = add_fetch_to_states(f);
		BOOST_REQUIRE(error == NULL);

		BOOST_CHECK(fetch_events.size() == 1);
		cJSON *json = fetch_events.front();
		fetch_events.pop_front();
		event event = get_event_from_json(json);
		BOOST_CHECK(event == ADD_EVENT);
		cJSON_Delete(json);
		remove_all_fetchers_from_peer(fetch_peer_1);
		cJSON_Delete(params);
	}

	{
		struct fetch *f = NULL;
		cJSON *params = create_fetch_params("", path_startsWith, "", "", 0);
		cJSON *error = add_fetch_to_peer(fetch_peer_1, params, &f);
		BOOST_REQUIRE(error == NULL);
		error = add_fetch_to_states(f);
		BOOST_REQUIRE(error == NULL);

		BOOST_CHECK(fetch_events.size() == 1);
		cJSON *json = fetch_events.front();
		fetch_events.pop_front();
		event event = get_event_from_json(json);
		BOOST_CHECK(event == ADD_EVENT);
		cJSON_Delete(json);
		remove_all_fetchers_from_peer(fetch_peer_1);
		cJSON_Delete(params);
	}

	{
		struct fetch *f = NULL;
		cJSON *params = create_fetch_params("", "", path_endsWith, "", 0);
		cJSON *error = add_fetch_to_peer(fetch_peer_1, params, &f);
		BOOST_REQUIRE(error == NULL);
		error = add_fetch_to_states(f);
		BOOST_REQUIRE(error == NULL);

		BOOST_CHECK(fetch_events.size() == 1);
		cJSON *json = fetch_events.front();
		fetch_events.pop_front();
		event event = get_event_from_json(json);
		BOOST_CHECK(event == ADD_EVENT);
		cJSON_Delete(json);
		remove_all_fetchers_from_peer(fetch_peer_1);
		cJSON_Delete(params);
	}

	{
		struct fetch *f = NULL;
		cJSON *params = create_fetch_params("", "", "", path_contains, 0);
		cJSON *error = add_fetch_to_peer(fetch_peer_1, params, &f);
		BOOST_REQUIRE(error == NULL);
		error = add_fetch_to_states(f);
		BOOST_REQUIRE(error == NULL);

		BOOST_CHECK(fetch_events.size() == 1);
		cJSON *json = fetch_events.front();
		fetch_events.pop_front();
		event event = get_event_from_json(json);
		BOOST_CHECK(event == ADD_EVENT);
		cJSON_Delete(json);
		remove_all_fetchers_from_peer(fetch_peer_1);
		cJSON_Delete(params);
	}
}

BOOST_FIXTURE_TEST_CASE(fetch_matchers_ignoring_case, F)
{
	const char *path = "foo/bar";
	const char *path_upper = "FOO/BAR";
	const char *path_startsWith = "FOO";
	const char *path_endsWith = "BAR";
	const char *path_contains = "OO/BA";

	int state_value = 12345;

	{
		cJSON *value = cJSON_CreateNumber(state_value);

		cJSON *error = add_state_or_method_to_peer(owner_peer, path, value, 0x00);
		BOOST_CHECK(error == NULL);
		cJSON_Delete(value);
	}

	struct state_or_method *s = get_state(path);
	BOOST_CHECK(s->value->valueint == state_value);

	{
		struct fetch *f = NULL;
		cJSON *params = create_fetch_params(path_upper, "", "", "", 1);
		cJSON *error = add_fetch_to_peer(fetch_peer_1, params, &f);
		BOOST_REQUIRE(error == NULL);
		error = add_fetch_to_states(f);
		BOOST_REQUIRE(error == NULL);

		BOOST_CHECK(fetch_events.size() == 1);
		cJSON *json = fetch_events.front();
		fetch_events.pop_front();
		event event = get_event_from_json(json);
		BOOST_CHECK(event == ADD_EVENT);
		cJSON_Delete(json);
		remove_all_fetchers_from_peer(fetch_peer_1);
		cJSON_Delete(params);
	}

	{
		struct fetch *f = NULL;
		cJSON *params = create_fetch_params("", path_startsWith, "", "", 1);
		cJSON *error = add_fetch_to_peer(fetch_peer_1, params, &f);
		BOOST_REQUIRE(error == NULL);
		error = add_fetch_to_states(f);
		BOOST_REQUIRE(error == NULL);

		BOOST_CHECK(fetch_events.size() == 1);
		cJSON *json = fetch_events.front();
		fetch_events.pop_front();
		event event = get_event_from_json(json);
		BOOST_CHECK(event == ADD_EVENT);
		cJSON_Delete(json);
		remove_all_fetchers_from_peer(fetch_peer_1);
		cJSON_Delete(params);
	}

	{
		struct fetch *f = NULL;
		cJSON *params = create_fetch_params("", "", path_endsWith, "", 1);
		cJSON *error = add_fetch_to_peer(fetch_peer_1, params, &f);
		BOOST_REQUIRE(error == NULL);
		error = add_fetch_to_states(f);
		BOOST_REQUIRE(error == NULL);

		BOOST_CHECK(fetch_events.size() == 1);
		cJSON *json = fetch_events.front();
		fetch_events.pop_front();
		event event = get_event_from_json(json);
		BOOST_CHECK(event == ADD_EVENT);
		cJSON_Delete(json);
		remove_all_fetchers_from_peer(fetch_peer_1);
		cJSON_Delete(params);
	}

	{
		struct fetch *f = NULL;
		cJSON *params = create_fetch_params("", "", "", path_contains, 1);
		cJSON *error = add_fetch_to_peer(fetch_peer_1, params, &f);
		BOOST_REQUIRE(error == NULL);
		error = add_fetch_to_states(f);
		BOOST_REQUIRE(error == NULL);

		BOOST_CHECK(fetch_events.size() == 1);
		cJSON *json = fetch_events.front();
		fetch_events.pop_front();
		event event = get_event_from_json(json);
		BOOST_CHECK(event == ADD_EVENT);
		cJSON_Delete(json);
		remove_all_fetchers_from_peer(fetch_peer_1);
		cJSON_Delete(params);
	}
}

BOOST_FIXTURE_TEST_CASE(fetch_and_change_and_remove, F)
{
	const char *path = "foo/bar";

	int state_value = 12345;

	{
		/// does not fetch anything because nothing does match
		struct fetch *f = NULL;
		cJSON *params = create_fetch_params(path, "", "", "", 0);
		cJSON *error = add_fetch_to_peer(fetch_peer_1, params, &f);
		BOOST_REQUIRE(error == NULL);
		error = add_fetch_to_states(f);
		BOOST_REQUIRE(error == NULL);

		BOOST_CHECK(fetch_events.size() == 0);
		remove_all_fetchers_from_peer(fetch_peer_1);
		cJSON_Delete(params);
	}

	{
		cJSON *value = cJSON_CreateNumber(state_value);

		cJSON *error = add_state_or_method_to_peer(owner_peer, path, value, 0x00);
		BOOST_CHECK(error == NULL);

		cJSON_Delete(value);
	}

	struct state_or_method *s = get_state(path);
	BOOST_CHECK(s->value->valueint == state_value);


	{
		struct fetch *f = NULL;
		cJSON *params = create_fetch_params(path, "", "", "", 0);
		cJSON *error = add_fetch_to_peer(fetch_peer_1, params, &f);
		BOOST_REQUIRE(error == NULL);
		error = add_fetch_to_states(f);
		BOOST_REQUIRE(error == NULL);

		BOOST_CHECK(fetch_events.size() == 1);
		cJSON *json = fetch_events.front();
		fetch_events.pop_front();
		event event = get_event_from_json(json);
		BOOST_CHECK(event == ADD_EVENT);
		cJSON_Delete(json);

		cJSON *new_value = cJSON_CreateNumber(4321);
		error = change_state(owner_peer, path, new_value);
		BOOST_REQUIRE(error == NULL);
		cJSON_Delete(new_value);

		BOOST_CHECK(fetch_events.size() == 1);
		json = fetch_events.front();
		fetch_events.pop_front();
		event = get_event_from_json(json);
		BOOST_CHECK(event == CHANGE_EVENT);
		cJSON_Delete(json);

		remove_all_fetchers_from_peer(fetch_peer_1);
		cJSON_Delete(params);
	}


	{
		/// fetch removal of state
		struct fetch *f = NULL;
		cJSON *params = create_fetch_params(path, "", "", "", 0);
		cJSON *error = add_fetch_to_peer(fetch_peer_1, params, &f);
		BOOST_REQUIRE(error == NULL);
		error = add_fetch_to_states(f);
		BOOST_REQUIRE(error == NULL);

		remove_state_or_method_from_peer(owner_peer, path);

		BOOST_CHECK(fetch_events.size() == 2);
		cJSON *json = fetch_events.front();
		fetch_events.pop_front();
		event event = get_event_from_json(json);
		BOOST_CHECK(event == ADD_EVENT);
		cJSON_Delete(json);

		json = fetch_events.front();
		fetch_events.pop_front();
		event = get_event_from_json(json);
		BOOST_CHECK(event == REMOVE_EVENT);
		cJSON_Delete(json);

		cJSON_Delete(params);
	}
}

BOOST_FIXTURE_TEST_CASE(fetch_and_unfetch, F)
{
	struct fetch *f = NULL;
	cJSON *params = create_fetch_params("", "", "", "", 0);
	cJSON *error = add_fetch_to_peer(fetch_peer_1, params, &f);
	BOOST_REQUIRE(error == NULL);
	cJSON_Delete(params);

	params = create_unfetch_params();
	error = remove_fetch_from_peer(fetch_peer_1, params);
	BOOST_REQUIRE(error == NULL);
	cJSON_Delete(params);
}

BOOST_FIXTURE_TEST_CASE(double_fetch, F)
{
	struct fetch *f = NULL;
	cJSON *params = create_fetch_params("", "", "", "", 0);
	cJSON *error = add_fetch_to_peer(fetch_peer_1, params, &f);
	BOOST_REQUIRE(error == NULL);

	error = add_fetch_to_peer(fetch_peer_1, params, &f);
	BOOST_REQUIRE(error != NULL);
	check_invalid_params(error);
	cJSON_Delete(params);
	cJSON_Delete(error);
}

BOOST_FIXTURE_TEST_CASE(add_events_before_fetch_response, F)
{
	static const char *path = "foo/bar";
	static const int fetch_id = 7386;
	static const int add_id = 777;

	cJSON *add = create_correct_add_state(path, add_id, 124);
	char *unformatted_json = cJSON_PrintUnformatted(add);
	cJSON_Delete(add);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), owner_peer);
	cJSON_free(unformatted_json);
	BOOST_REQUIRE(ret == 0);

	cJSON *fetch = create_correct_fetch("foo/bar", fetch_id);
	unformatted_json = cJSON_PrintUnformatted(fetch);
	cJSON_Delete(fetch);
	ret = parse_message(unformatted_json, strlen(unformatted_json), fetch_peer_1);
	cJSON_free(unformatted_json);
	BOOST_REQUIRE(ret == 0);

	BOOST_CHECK(fetch_events.size() == 2);
	cJSON *json = fetch_events.front();
	fetch_events.pop_front();
	event event = get_event_from_json(json);
	BOOST_CHECK(event == ADD_EVENT);
	cJSON_Delete(json);

	json = fetch_events.front();
	fetch_events.pop_front();
	check_response(json, fetch_id);
	cJSON_Delete(json);
}

BOOST_FIXTURE_TEST_CASE(set_with_return_value, F)
{
	static const char *path = "foo/bar";
	static const int fetch_id = 7386;
	static const int add_id = 777;

	cJSON *add = create_correct_add_state(path, add_id, 124);
	char *unformatted_json = cJSON_PrintUnformatted(add);
	cJSON_Delete(add);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), owner_peer);
	cJSON_free(unformatted_json);
	BOOST_REQUIRE(ret == 0);
	check_no_error(add_id);

	cJSON *fetch = create_correct_fetch("foo/bar", fetch_id);
	unformatted_json = cJSON_PrintUnformatted(fetch);
	cJSON_Delete(fetch);
	ret = parse_message(unformatted_json, strlen(unformatted_json), fetch_peer_1);
	cJSON_free(unformatted_json);
	BOOST_REQUIRE(ret == 0);

	BOOST_CHECK(fetch_events.size() == 2);
	cJSON *json = fetch_events.front();
	fetch_events.pop_front();
	event event = get_event_from_json(json);
	BOOST_CHECK(event == ADD_EVENT);
	cJSON_Delete(json);

	json = fetch_events.front();
	fetch_events.pop_front();
	check_response(json, fetch_id);
	cJSON_Delete(json);

	cJSON *set_json = create_correct_set_method(path, 124);
	unformatted_json = cJSON_PrintUnformatted(set_json);
	ret = parse_message(unformatted_json, strlen(unformatted_json), set_peer);
	cJSON_free(unformatted_json);
	cJSON_Delete(set_json);
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(owner_responses.size() == 1);
	char *routed_id = get_routed_id(owner_responses.front());
	json = owner_responses.front();
	owner_responses.pop_front();
	cJSON_Delete(json);

	cJSON *result_json = create_result_json(routed_id);
	unformatted_json = cJSON_PrintUnformatted(result_json);
	ret = parse_message(unformatted_json, strlen(unformatted_json), owner_peer);
	cJSON_free(unformatted_json);
	cJSON_Delete(result_json);
	BOOST_CHECK(ret == 0);
	free(routed_id);

	BOOST_CHECK(fetch_events.size() == 1);
}
