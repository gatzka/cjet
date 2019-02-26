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
#define BOOST_TEST_MODULE parse JSON

#include <boost/test/unit_test.hpp>

#include <cstring>
#include <list>

#include "alloc.h"
#include "compiler.h"
#include "element.h"
#include "generated/cjet_config.h"
#include "json/cJSON.h"
#include "parse.h"
#include "peer.h"
#include "table.h"

static std::list<cJSON*> events;

extern "C" {
	cjet_ssize_t socket_read(socket_type sock, void *buf, size_t count)
	{
		(void)sock;
		(void)count;
		uint64_t number_of_timeouts = 1;
		::memcpy(buf, &number_of_timeouts, sizeof(number_of_timeouts));
		return 8;
	}

	int socket_close(socket_type sock)
	{
		(void)sock;
		return 0;
	}
}

static cJSON *parse_send_buffer(const char *json)
{
	const char *end_parse;
	cJSON *root = cJSON_ParseWithOpts(json, &end_parse, 0);
	return root;
}

int send_message(const struct peer *p, char *rendered, size_t len)
{
	(void)len;
	(void)p;
	cJSON *fetch_event = parse_send_buffer(rendered);
	events.push_back(fetch_event);
	return 0;
}

static enum eventloop_return fake_add(const void *this_ptr, const struct io_event *ev)
{
	(void)this_ptr;
	(void)ev;
	return EL_CONTINUE_LOOP;
}

static void fake_remove(void *this_ptr, const struct io_event *ev)
{
	(void)this_ptr;
	(void)ev;
	return;
}

static struct eventloop loop;

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
		init_peer(&p, false, &loop);
		p.send_message = send_message;
		init_peer(&set_peer, false, &loop);
		set_peer.send_message = send_message;
		element_hashtable_create();
	}

	~F()
	{
		free_peer_resources(&p);
		free_peer_resources(&set_peer);
		while (!events.empty()) {
			cJSON *ptr = events.front();
			events.pop_front();
			cJSON_Delete(ptr);
		}
		element_hashtable_delete();
	}

	struct peer p;
	struct peer set_peer;
};

static struct element *get_state(const char *path)
{
	return (struct element *)element_table_get(path);
}

static cJSON *create_correct_add_state(const char *path)
{
	cJSON *root = cJSON_CreateObject();
	BOOST_REQUIRE(root != NULL);
	cJSON_AddNumberToObject(root, "id", 7384);
	cJSON_AddStringToObject(root, "method", "add");

	cJSON *params = cJSON_CreateObject();
	BOOST_REQUIRE(params != NULL);
	cJSON_AddStringToObject(params, "path", path);
	cJSON_AddNumberToObject(params, "value", 123);
	cJSON_AddItemToObject(root, "params", params);
	return root;
}

static cJSON *create_correct_add_state_with_timeout(const char *path, double timeout_s)
{
	cJSON *root = create_correct_add_state(path);
	cJSON *params = cJSON_GetObjectItem(root, "params");
	cJSON_AddNumberToObject(params, "timeout", timeout_s);
	return root;
}

static cJSON *create_correct_add_method()
{
	cJSON *root = cJSON_CreateObject();
	BOOST_REQUIRE(root != NULL);
	cJSON_AddNumberToObject(root, "id", 7384);
	cJSON_AddStringToObject(root, "method", "add");

	cJSON *params = cJSON_CreateObject();
	BOOST_REQUIRE(params != NULL);
	cJSON_AddStringToObject(params, "path", "/foo/bar/method/");
	cJSON_AddItemToObject(root, "params", params);
	return root;
}

static cJSON *create_correct_config_method()
{
	cJSON *root = cJSON_CreateObject();
	BOOST_REQUIRE(root != NULL);
	cJSON_AddNumberToObject(root, "id", 7384);
	cJSON_AddStringToObject(root, "method", "config");

	cJSON *params = cJSON_CreateObject();
	BOOST_REQUIRE(params != NULL);
	cJSON_AddItemToObject(root, "params", params);
	return root;
}

static cJSON *create_two_method_json()
{
	cJSON *array = cJSON_CreateArray();
	BOOST_REQUIRE(array != NULL);
	cJSON *method_1 = create_correct_add_state("/foo/bar/state1");
	cJSON *method_2 = create_correct_add_state("/foo/bar/state2");
	cJSON_AddItemToArray(array, method_1);
	cJSON_AddItemToArray(array, method_2);
	return array;
}

static cJSON *create_json_no_method()
{
	cJSON *root = cJSON_CreateObject();
	BOOST_REQUIRE(root != NULL);
	cJSON_AddNumberToObject(root, "id", 7384);
	cJSON_AddStringToObject(root, "meth", "add");

	cJSON *params = cJSON_CreateObject();
	BOOST_REQUIRE(params != NULL);
	cJSON_AddStringToObject(params, "path", "/foo/bar/state/");
	cJSON_AddNumberToObject(params, "value", 123);
	cJSON_AddItemToObject(root, "params", params);
	return root;
}

static cJSON *create_result_json(const char *id)
{
	cJSON *root = cJSON_CreateObject();
	BOOST_REQUIRE(root != NULL);
	cJSON_AddStringToObject(root, "id", id);
	cJSON *result = cJSON_CreateObject();
	BOOST_REQUIRE(result != NULL);
	cJSON_AddItemToObject(root, "result", result);
	return root;
}

static cJSON *create_error_json(const char *id)
{
	cJSON *root = cJSON_CreateObject();
	BOOST_REQUIRE(root != NULL);
	cJSON_AddStringToObject(root, "id", id);
	cJSON *error = cJSON_CreateObject();
	BOOST_REQUIRE(error != NULL);
	cJSON_AddItemToObject(root, "error", error);
	return root;
}

static cJSON *create_json_no_string_method()
{
	cJSON *root = cJSON_CreateObject();
	BOOST_REQUIRE(root != NULL);
	cJSON_AddNumberToObject(root, "id", 7384);
	cJSON_AddNumberToObject(root, "method", 123);

	cJSON *params = cJSON_CreateObject();
	BOOST_REQUIRE(params != NULL);
	cJSON_AddStringToObject(params, "path", "/foo/bar/state/");
	cJSON_AddNumberToObject(params, "value", 123);
	cJSON_AddItemToObject(root, "params", params);
	return root;
}

static cJSON *create_json_unsupported_method()
{
	cJSON *root = cJSON_CreateObject();
	BOOST_REQUIRE(root != NULL);
	cJSON_AddNumberToObject(root, "id", 7384);
	cJSON_AddStringToObject(root, "method", "horst");

	cJSON *params = cJSON_CreateObject();
	BOOST_REQUIRE(params != NULL);
	cJSON_AddStringToObject(params, "path", "/foo/bar/state/");
	cJSON_AddNumberToObject(params, "value", 123);
	cJSON_AddItemToObject(root, "params", params);
	return root;
}

static cJSON *create_add_without_path()
{
	cJSON *root = cJSON_CreateObject();
	BOOST_REQUIRE(root != NULL);
	cJSON_AddNumberToObject(root, "id", 7384);
	cJSON_AddStringToObject(root, "method", "add");

	cJSON *params = cJSON_CreateObject();
	BOOST_REQUIRE(params != NULL);
	cJSON_AddNumberToObject(params, "value", 123);
	cJSON_AddItemToObject(root, "params", params);
	return root;
}

static cJSON *create_add_state_with_fetchonly(bool fetch_only)
{
	cJSON *root = cJSON_CreateObject();
	BOOST_REQUIRE(root != NULL);
	cJSON_AddNumberToObject(root, "id", 7384);
	cJSON_AddStringToObject(root, "method", "add");

	cJSON *params = cJSON_CreateObject();
	BOOST_REQUIRE(params != NULL);
	cJSON_AddStringToObject(params, "path", "/foo/bar/state/");
	cJSON_AddNumberToObject(params, "value", 123);
	if (fetch_only) {
		cJSON_AddTrueToObject(params, "fetchOnly");
	} else {
		cJSON_AddFalseToObject(params, "fetchOnly");
	}
	cJSON_AddItemToObject(root, "params", params);
	return root;
}

static cJSON *create_add_state_with_illegal_fetchonly()
{
	cJSON *root = cJSON_CreateObject();
	BOOST_REQUIRE(root != NULL);
	cJSON_AddNumberToObject(root, "id", 7384);
	cJSON_AddStringToObject(root, "method", "add");

	cJSON *params = cJSON_CreateObject();
	BOOST_REQUIRE(params != NULL);
	cJSON_AddStringToObject(params, "path", "/foo/bar/state/");
	cJSON_AddNumberToObject(params, "value", 123);
	cJSON_AddNumberToObject(params, "fetchOnly", 123);
	cJSON_AddItemToObject(root, "params", params);
	return root;
}

static cJSON *create_correct_remove(const char *what)
{
	cJSON *root = cJSON_CreateObject();
	BOOST_REQUIRE(root != NULL);
	cJSON_AddNumberToObject(root, "id", 7384);
	cJSON_AddStringToObject(root, "method", "remove");

	cJSON *params = cJSON_CreateObject();
	BOOST_REQUIRE(params != NULL);
	cJSON_AddStringToObject(params, "path", what);
	cJSON_AddItemToObject(root, "params", params);
	return root;
}

static cJSON *create_remove_without_path()
{
	cJSON *root = cJSON_CreateObject();
	BOOST_REQUIRE(root != NULL);
	cJSON_AddNumberToObject(root, "id", 7384);
	cJSON_AddStringToObject(root, "method", "remove");

	cJSON *params = cJSON_CreateObject();
	BOOST_REQUIRE(params != NULL);
	cJSON_AddItemToObject(root, "params", params);
	return root;
}

static cJSON *create_path_no_string()
{
	cJSON *root = cJSON_CreateObject();
	BOOST_REQUIRE(root != NULL);
	cJSON_AddNumberToObject(root, "id", 7384);
	cJSON_AddStringToObject(root, "method", "add");

	cJSON *params = cJSON_CreateObject();
	BOOST_REQUIRE(params != NULL);
	cJSON_AddNumberToObject(params, "path", 123);
	cJSON_AddNumberToObject(params, "value", 123);
	cJSON_AddItemToObject(root, "params", params);
	return root;
}

static cJSON *create_json_no_params()
{
	cJSON *root = cJSON_CreateObject();
	BOOST_REQUIRE(root != NULL);
	cJSON_AddNumberToObject(root, "id", 7384);
	cJSON_AddStringToObject(root, "method", "add");
	return root;
}

static cJSON *create_correct_fetch()
{
	cJSON *root = cJSON_CreateObject();
	BOOST_REQUIRE(root != NULL);
	cJSON_AddNumberToObject(root, "id", 7384);
	cJSON_AddStringToObject(root, "method", "fetch");

	cJSON *params = cJSON_CreateObject();
	BOOST_REQUIRE(params != NULL);
	cJSON_AddStringToObject(params, "id", "123456");
	cJSON_AddItemToObject(root, "params", params);

	cJSON *path = cJSON_CreateObject();
	BOOST_REQUIRE(path != NULL);
	cJSON_AddStringToObject(path, "equals", "person");
	cJSON_AddStringToObject(path, "startsWith", "per");
	cJSON_AddItemToObject(params, "path", path);
	return root;
}

static cJSON *create_correct_unfetch()
{
	cJSON *root = cJSON_CreateObject();
	BOOST_REQUIRE(root != NULL);
	cJSON_AddNumberToObject(root, "id", 7384);
	cJSON_AddStringToObject(root, "method", "unfetch");

	cJSON *params = cJSON_CreateObject();
	BOOST_REQUIRE(params != NULL);
	cJSON_AddStringToObject(params, "id", "123456");
	cJSON_AddItemToObject(root, "params", params);
	return root;
}

static cJSON *create_correct_call_method()
{
	cJSON *root = cJSON_CreateObject();
	BOOST_REQUIRE(root != NULL);
	cJSON_AddNumberToObject(root, "id", 7384);
	cJSON_AddStringToObject(root, "method", "call");

	cJSON *params = cJSON_CreateObject();
	BOOST_REQUIRE(params != NULL);
	cJSON_AddStringToObject(params, "path", "/foo/bar/state/");
	cJSON_AddItemToObject(root, "params", params);
	return root;
}

static cJSON *create_call_without_path()
{
	cJSON *root = cJSON_CreateObject();
	BOOST_REQUIRE(root != NULL);
	cJSON_AddNumberToObject(root, "id", 7384);
	cJSON_AddStringToObject(root, "method", "call");

	cJSON *params = cJSON_CreateObject();
	BOOST_REQUIRE(params != NULL);
	cJSON_AddItemToObject(root, "params", params);
	return root;
}

static cJSON *create_correct_change_method(const char *path)
{
	cJSON *root = cJSON_CreateObject();
	BOOST_REQUIRE(root != NULL);
	cJSON_AddNumberToObject(root, "id", 7384);
	cJSON_AddStringToObject(root, "method", "change");

	cJSON *params = cJSON_CreateObject();
	BOOST_REQUIRE(params != NULL);
	cJSON_AddStringToObject(params, "path", path);
	cJSON_AddNumberToObject(params, "value", 123);
	cJSON_AddItemToObject(root, "params", params);
	return root;
}

static cJSON *create_change_without_path()
{
	cJSON *root = cJSON_CreateObject();
	BOOST_REQUIRE(root != NULL);
	cJSON_AddNumberToObject(root, "id", 7384);
	cJSON_AddStringToObject(root, "method", "change");

	cJSON *params = cJSON_CreateObject();
	BOOST_REQUIRE(params != NULL);
	cJSON_AddNumberToObject(params, "value", 123);
	cJSON_AddItemToObject(root, "params", params);
	return root;
}

static cJSON *create_change_without_value()
{
	cJSON *root = cJSON_CreateObject();
	BOOST_REQUIRE(root != NULL);
	cJSON_AddNumberToObject(root, "id", 7384);
	cJSON_AddStringToObject(root, "method", "change");

	cJSON *params = cJSON_CreateObject();
	BOOST_REQUIRE(params != NULL);
	cJSON_AddStringToObject(params, "path", "/foo/bar/state/");
	cJSON_AddItemToObject(root, "params", params);
	return root;
}

static cJSON *create_correct_set_method(const char *path)
{
	cJSON *root = cJSON_CreateObject();
	BOOST_REQUIRE(root != NULL);
	cJSON_AddNumberToObject(root, "id", 7384);
	cJSON_AddStringToObject(root, "method", "set");

	cJSON *params = cJSON_CreateObject();
	BOOST_REQUIRE(params != NULL);
	cJSON_AddStringToObject(params, "path", path);
	cJSON_AddNumberToObject(params, "value", 123);
	cJSON_AddItemToObject(root, "params", params);
	return root;
}

static cJSON *create_set_without_params()
{
	cJSON *root = cJSON_CreateObject();
	BOOST_REQUIRE(root != NULL);
	cJSON_AddNumberToObject(root, "id", 7384);
	cJSON_AddStringToObject(root, "method", "set");

	return root;
}

static cJSON *create_set_without_path()
{
	cJSON *root = cJSON_CreateObject();
	BOOST_REQUIRE(root != NULL);
	cJSON_AddNumberToObject(root, "id", 7384);
	cJSON_AddStringToObject(root, "method", "set");

	cJSON *params = cJSON_CreateObject();
	BOOST_REQUIRE(params != NULL);
	cJSON_AddNumberToObject(params, "value", 123);
	cJSON_AddItemToObject(root, "params", params);
	return root;
}

static cJSON *create_set_without_path_and_no_id()
{
	cJSON *root = cJSON_CreateObject();
	BOOST_REQUIRE(root != NULL);
	cJSON_AddStringToObject(root, "method", "set");

	cJSON *params = cJSON_CreateObject();
	BOOST_REQUIRE(params != NULL);
	cJSON_AddNumberToObject(params, "value", 123);
	cJSON_AddItemToObject(root, "params", params);
	return root;
}

static cJSON *create_set_without_value()
{
	cJSON *root = cJSON_CreateObject();
	BOOST_REQUIRE(root != NULL);
	cJSON_AddNumberToObject(root, "id", 7384);
	cJSON_AddStringToObject(root, "method", "set");

	cJSON *params = cJSON_CreateObject();
	BOOST_REQUIRE(params != NULL);
	cJSON_AddStringToObject(params, "path", "/foo/bar/state/");
	cJSON_AddItemToObject(root, "params", params);
	return root;
}

static void check_invalid_params_error()
{
	cJSON *response = events.front();
	events.pop_front();
	BOOST_REQUIRE(response != NULL);

	cJSON *error = cJSON_GetObjectItem(response, "error");
	BOOST_REQUIRE(error != NULL);

	cJSON *code = cJSON_GetObjectItem(error, "code");
	if (code != NULL) {
		BOOST_REQUIRE(code->type == cJSON_Number);
		BOOST_CHECK(code->valueint == -32602);
	} else {
		BOOST_FAIL("No code object!");
	}
	cJSON_Delete(response);
}

static char *get_routed_id(const cJSON *json)
{
	cJSON *id = cJSON_GetObjectItem(json, "id");
	if (id == NULL) {
		BOOST_FAIL("No id in JSON object!");
		return NULL;
	} else {
		BOOST_REQUIRE(id != NULL);
		BOOST_REQUIRE(id->type == cJSON_String);
		return strdup(id->valuestring);
	}
}

static void check_no_error()
{
	cJSON *response = events.front();
	events.pop_front();
	BOOST_REQUIRE(response != NULL);

	const cJSON *error = cJSON_GetObjectItem(response, "error");
	BOOST_CHECK(error == NULL);
	cJSON_Delete(response);
}

static cJSON *create_correct_info_method()
{
	cJSON *root = cJSON_CreateObject();
	BOOST_REQUIRE(root != NULL);
	cJSON_AddNumberToObject(root, "id", 7384);
	cJSON_AddStringToObject(root, "method", "info");

	cJSON *params = cJSON_CreateObject();
	BOOST_REQUIRE(params != NULL);
	cJSON_AddItemToObject(root, "params", params);
	return root;
}

static cJSON *create_correct_info_method_without_params()
{
	cJSON *root = cJSON_CreateObject();
	BOOST_REQUIRE(root != NULL);
	cJSON_AddNumberToObject(root, "id", 7384);
	cJSON_AddStringToObject(root, "method", "info");

	return root;
}

static double convert_nsecs_to_seconds(uint64_t nsecs)
{
	return (double)nsecs / 1000000000.0;
}

BOOST_FIXTURE_TEST_CASE(parse_correct_json, F)
{
	cJSON *correct_json = create_correct_add_state("/foo/bar/state");
	char *unformatted_json = cJSON_PrintUnformatted(correct_json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), &p);
	cjet_free(unformatted_json);
	cJSON_Delete(correct_json);
	BOOST_CHECK(ret == 0);
}

BOOST_FIXTURE_TEST_CASE(parse_add_state_with_timeout, F)
{
	double timeout_s = 2.34;
	const char path[] = "/foo/bar/state";
	cJSON *correct_json = create_correct_add_state_with_timeout(path, timeout_s);
	char *unformatted_json = cJSON_PrintUnformatted(correct_json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), &p);
	cjet_free(unformatted_json);
	cJSON_Delete(correct_json);
	BOOST_CHECK(ret == 0);

	struct element *e = get_state(path);
	BOOST_CHECK_CLOSE(convert_nsecs_to_seconds(e->timeout_nsec), timeout_s, 0.1);
}

BOOST_FIXTURE_TEST_CASE(parse_add_state_with_small_timeout, F)
{
	double timeout_s = 0.0009;
	const char path[] = "/foo/bar/state";
	cJSON *correct_json = create_correct_add_state_with_timeout(path, timeout_s);
	char *unformatted_json = cJSON_PrintUnformatted(correct_json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), &p);
	cjet_free(unformatted_json);
	cJSON_Delete(correct_json);
	BOOST_CHECK(ret == 0);

	struct element *e = get_state(path);
	BOOST_CHECK_MESSAGE(e == NULL, "State added despite small timeout value!");
	check_invalid_params_error();
}

BOOST_FIXTURE_TEST_CASE(parse_add_state_with_negative_timeout, F)
{
	double timeout_s = -2.34;
	const char path[] = "/foo/bar/state";
	cJSON *correct_json = create_correct_add_state_with_timeout(path, timeout_s);
	char *unformatted_json = cJSON_PrintUnformatted(correct_json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), &p);
	cjet_free(unformatted_json);
	cJSON_Delete(correct_json);
	BOOST_CHECK(ret == 0);

	struct element *e = get_state(path);
	BOOST_CHECK_MESSAGE(e == NULL, "State added despite negative timeout value!");
	check_invalid_params_error();
}

BOOST_FIXTURE_TEST_CASE(parse_add_state_with_illegal_timeout, F)
{
	const char path[] = "/foo/bar/state";
	cJSON *correct_json = create_correct_add_state(path);
	cJSON *params = cJSON_GetObjectItem(correct_json, "params");
	cJSON_AddStringToObject(params, "timeout", "hello");
	char *unformatted_json = cJSON_PrintUnformatted(correct_json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), &p);
	cjet_free(unformatted_json);
	cJSON_Delete(correct_json);
	BOOST_CHECK(ret == 0);

	struct element *e = get_state(path);
	BOOST_CHECK_MESSAGE(e == NULL, "State added even with wrong timeout!");
	check_invalid_params_error();
}

BOOST_AUTO_TEST_CASE(length_too_long)
{
	if (CONFIG_CHECK_JSON_LENGTH) {
		cJSON *correct_json = create_correct_add_state("/foo/bar/state");
		char *unformatted_json = cJSON_PrintUnformatted(correct_json);
		int ret = parse_message(unformatted_json, strlen(unformatted_json) + 1, NULL);
		cjet_free(unformatted_json);
		cJSON_Delete(correct_json);

		BOOST_CHECK(ret == -1);
	}
}

BOOST_AUTO_TEST_CASE(length_too_short)
{
	if (CONFIG_CHECK_JSON_LENGTH) {
		cJSON *correct_json = create_correct_add_state("/foo/bar/state");
		char *unformatted_json = cJSON_PrintUnformatted(correct_json);
		int ret = parse_message(unformatted_json, strlen(unformatted_json) - 1, NULL);
		cjet_free(unformatted_json);
		cJSON_Delete(correct_json);

		BOOST_CHECK(ret == -1);
	}
}

BOOST_FIXTURE_TEST_CASE(two_method, F)
{
	cJSON *array = create_two_method_json();
	char *unformatted_json = cJSON_PrintUnformatted(array);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), &p);
	cjet_free(unformatted_json);
	cJSON_Delete(array);
	BOOST_CHECK(ret == 0);
}

BOOST_FIXTURE_TEST_CASE(wrong_array, F)
{
	const int numbers[2] = {1,2};
	cJSON *root = cJSON_CreateIntArray(numbers, 2);
	char *unformatted_json = cJSON_PrintUnformatted(root);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), &p);
	cjet_free(unformatted_json);
	cJSON_Delete(root);

	BOOST_CHECK(ret == -1);
}

BOOST_FIXTURE_TEST_CASE(add_without_path_test, F)
{
	cJSON *json = create_add_without_path();
	char *unformatted_json = cJSON_PrintUnformatted(json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), &p);
	cjet_free(unformatted_json);
	cJSON_Delete(json);
	BOOST_CHECK(ret == 0);
}

BOOST_FIXTURE_TEST_CASE(add_with_fetchonly_true, F)
{
	cJSON *correct_json = create_add_state_with_fetchonly(true);
	char *unformatted_json = cJSON_PrintUnformatted(correct_json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), &p);
	cjet_free(unformatted_json);
	cJSON_Delete(correct_json);
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(events.size() == 1);
	check_no_error();
}

BOOST_FIXTURE_TEST_CASE(add_with_fetchonly_false, F)
{
	cJSON *correct_json = create_add_state_with_fetchonly(false);
	char *unformatted_json = cJSON_PrintUnformatted(correct_json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), &p);
	cjet_free(unformatted_json);
	cJSON_Delete(correct_json);
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(events.size() == 1);
	check_no_error();
}

BOOST_FIXTURE_TEST_CASE(add_with_illegal_fetchonly_false, F)
{
	cJSON *correct_json = create_add_state_with_illegal_fetchonly();
	char *unformatted_json = cJSON_PrintUnformatted(correct_json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), &p);
	cjet_free(unformatted_json);
	cJSON_Delete(correct_json);
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(events.size() == 1);
	check_invalid_params_error();
}

BOOST_FIXTURE_TEST_CASE(correct_remove_state_test, F)
{
	static const char path[] = "/foo/bar/state/";

	cJSON *add_json = create_correct_add_state(path);
	char *unformatted_json = cJSON_PrintUnformatted(add_json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), &p);
	cjet_free(unformatted_json);
	cJSON_Delete(add_json);
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(events.size() == 1);
	check_no_error();

	cJSON *remove_json = create_correct_remove(path);
	unformatted_json = cJSON_PrintUnformatted(remove_json);
	ret = parse_message(unformatted_json, strlen(unformatted_json), &p);
	cjet_free(unformatted_json);
	cJSON_Delete(remove_json);
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(events.size() == 1);
	check_no_error();
}

BOOST_FIXTURE_TEST_CASE(correct_add_method_test, F)
{
	cJSON *correct_json = create_correct_add_method();
	char *unformatted_json = cJSON_PrintUnformatted(correct_json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), &p);
	cjet_free(unformatted_json);
	cJSON_Delete(correct_json);
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(events.size() == 1);
	check_no_error();
}

BOOST_FIXTURE_TEST_CASE(correct_remove_method_test, F)
{
	cJSON *add_json = create_correct_add_method();
	char *unformatted_json = cJSON_PrintUnformatted(add_json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), &p);
	cjet_free(unformatted_json);
	cJSON_Delete(add_json);
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(events.size() == 1);
	check_no_error();

	cJSON *remove_json = create_correct_remove("/foo/bar/method/");
	unformatted_json = cJSON_PrintUnformatted(remove_json);
	ret = parse_message(unformatted_json, strlen(unformatted_json), &p);
	cjet_free(unformatted_json);
	cJSON_Delete(remove_json);
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(events.size() == 1);
	check_no_error();
}

BOOST_FIXTURE_TEST_CASE(remove_non_existing_state_or_method, F)
{
	cJSON *json = create_correct_remove("non_exist");
	char *unformatted_json = cJSON_PrintUnformatted(json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), &p);
	cjet_free(unformatted_json);
	cJSON_Delete(json);
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(events.size() == 1);
	check_invalid_params_error();
}

BOOST_FIXTURE_TEST_CASE(remove_without_path_test, F)
{
	cJSON *json = create_remove_without_path();
	char *unformatted_json = cJSON_PrintUnformatted(json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), &p);
	cjet_free(unformatted_json);
	cJSON_Delete(json);
	BOOST_CHECK(ret == 0);
}

BOOST_FIXTURE_TEST_CASE(path_no_string_test, F)
{
	cJSON *json = create_path_no_string();
	char *unformatted_json = cJSON_PrintUnformatted(json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), &p);
	cjet_free(unformatted_json);
	cJSON_Delete(json);
	BOOST_CHECK(ret == 0);
}

BOOST_FIXTURE_TEST_CASE(no_params_test, F)
{
	cJSON *json = create_json_no_params();
	char *unformatted_json = cJSON_PrintUnformatted(json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), &p);
	cjet_free(unformatted_json);
	cJSON_Delete(json);
	BOOST_CHECK(ret == 0);
}

BOOST_FIXTURE_TEST_CASE(unsupported_method, F)
{
	cJSON *json = create_json_unsupported_method();
	char *unformatted_json = cJSON_PrintUnformatted(json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), &p);
	cjet_free(unformatted_json);
	cJSON_Delete(json);
	BOOST_CHECK(ret == 0);
}

BOOST_FIXTURE_TEST_CASE(no_method, F)
{
	cJSON *json = create_json_no_method();
	char *unformatted_json = cJSON_PrintUnformatted(json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), &p);
	cjet_free(unformatted_json);
	cJSON_Delete(json);
	BOOST_CHECK(ret == 0);
}

BOOST_FIXTURE_TEST_CASE(no_string_method, F)
{
	cJSON *json = create_json_no_string_method();
	char *unformatted_json = cJSON_PrintUnformatted(json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), &p);
	cjet_free(unformatted_json);
	cJSON_Delete(json);
	BOOST_CHECK(ret == 0);
}

BOOST_FIXTURE_TEST_CASE(correct_set_with_error_response, F)
{
	static const char path[] = "/foo/bar/state";

	cJSON *add_json = create_correct_add_state(path);
	char *unformatted_json = cJSON_PrintUnformatted(add_json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), &p);
	cjet_free(unformatted_json);
	cJSON_Delete(add_json);
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(events.size() == 1);
	check_no_error();

	cJSON *set_json = create_correct_set_method(path);
	unformatted_json = cJSON_PrintUnformatted(set_json);
	ret = parse_message(unformatted_json, strlen(unformatted_json), &set_peer);
	cjet_free(unformatted_json);
	cJSON_Delete(set_json);
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(events.size() == 1);
	char *routed_id = get_routed_id(events.front());
	check_no_error();

	cJSON *result_json = create_error_json(routed_id);
	unformatted_json = cJSON_PrintUnformatted(result_json);
	ret = parse_message(unformatted_json, strlen(unformatted_json), &p);
	cjet_free(unformatted_json);
	cJSON_Delete(result_json);
	BOOST_CHECK(ret == 0);
	free(routed_id);
}

BOOST_FIXTURE_TEST_CASE(parse_wrong_json, F)
{
	static const char wrong_json[] =   "{\"id\": 7384,\"method\": add\",\"params\":{\"path\": \"foo/bar/state\",\"value\": 123}}";
	int ret = parse_message(wrong_json, strlen(wrong_json), &p);
	BOOST_CHECK(ret == -1);
}

BOOST_FIXTURE_TEST_CASE(parse_json_no_object_or_array, F)
{
	static const char json[] = "\"foo\"";
	int ret = parse_message(json, strlen(json), &p);
	BOOST_CHECK(ret == -1);
}

BOOST_FIXTURE_TEST_CASE(correct_fetch_test, F)
{
	cJSON *json = create_correct_fetch();
	char *unformatted_json = cJSON_PrintUnformatted(json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), &p);
	cjet_free(unformatted_json);
	cJSON_Delete(json);
	BOOST_CHECK(ret == 0);
}

BOOST_FIXTURE_TEST_CASE(correct_unfetch_test, F)
{
	cJSON *json = create_correct_unfetch();
	char *unformatted_json = cJSON_PrintUnformatted(json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), &p);
	cjet_free(unformatted_json);
	cJSON_Delete(json);
	BOOST_CHECK(ret == 0);
}

BOOST_FIXTURE_TEST_CASE(correct_config_test, F)
{
	cJSON *json = create_correct_config_method();
	char *unformatted_json = cJSON_PrintUnformatted(json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), &p);
	cjet_free(unformatted_json);
	cJSON_Delete(json);
	BOOST_CHECK(ret == 0);
}

BOOST_FIXTURE_TEST_CASE(correct_call_method_test, F)
{
	cJSON *correct_json = create_correct_call_method();
	char *unformatted_json = cJSON_PrintUnformatted(correct_json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), &p);
	cjet_free(unformatted_json);
	cJSON_Delete(correct_json);
	BOOST_CHECK(ret == 0);
}

BOOST_FIXTURE_TEST_CASE(call_without_path_test, F)
{
	cJSON *json = create_call_without_path();
	char *unformatted_json = cJSON_PrintUnformatted(json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), &p);
	cjet_free(unformatted_json);
	cJSON_Delete(json);
	BOOST_CHECK(ret == 0);
}

BOOST_FIXTURE_TEST_CASE(correct_change, F)
{
	static const char path[] = "/foo/bar/state";
	cJSON *add_json = create_correct_add_state(path);
	char *unformatted_json = cJSON_PrintUnformatted(add_json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), &p);
	cjet_free(unformatted_json);
	cJSON_Delete(add_json);
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(events.size() == 1);
	check_no_error();

	cJSON *set_json = create_correct_change_method(path);
	unformatted_json = cJSON_PrintUnformatted(set_json);
	ret = parse_message(unformatted_json, strlen(unformatted_json), &p);
	cjet_free(unformatted_json);
	cJSON_Delete(set_json);
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(events.size() == 1);
	check_no_error();
}


BOOST_FIXTURE_TEST_CASE(change_without_path, F)
{
	cJSON *json = create_change_without_path();
	char *unformatted_json = cJSON_PrintUnformatted(json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), &p);
	cjet_free(unformatted_json);
	cJSON_Delete(json);
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(events.size() == 1);
	check_invalid_params_error();
}

BOOST_FIXTURE_TEST_CASE(change_without_value, F)
{
	cJSON *json = create_change_without_value();
	char *unformatted_json = cJSON_PrintUnformatted(json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), &p);
	cjet_free(unformatted_json);
	cJSON_Delete(json);
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(events.size() == 1);
	check_invalid_params_error();
}

BOOST_FIXTURE_TEST_CASE(correct_set, F)
{
	static const char path[] = "/foo/bar/state";

	cJSON *add_json = create_correct_add_state(path);
	char *unformatted_json = cJSON_PrintUnformatted(add_json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), &p);
	cjet_free(unformatted_json);
	cJSON_Delete(add_json);
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(events.size() == 1);
	check_no_error();

	cJSON *set_json = create_correct_set_method(path);
	unformatted_json = cJSON_PrintUnformatted(set_json);
	ret = parse_message(unformatted_json, strlen(unformatted_json), &set_peer);
	cjet_free(unformatted_json);
	cJSON_Delete(set_json);
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(events.size() == 1);
	char *routed_id = get_routed_id(events.front());
	check_no_error();

	cJSON *result_json = create_result_json(routed_id);
	unformatted_json = cJSON_PrintUnformatted(result_json);
	ret = parse_message(unformatted_json, strlen(unformatted_json), &p);
	cjet_free(unformatted_json);
	cJSON_Delete(result_json);
	BOOST_CHECK(ret == 0);
	free(routed_id);
}

BOOST_FIXTURE_TEST_CASE(set_without_path, F)
{
	static const char path[] = "/foo/bar/state";

	cJSON *add_json = create_correct_add_state(path);
	char *unformatted_json = cJSON_PrintUnformatted(add_json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), &p);
	cjet_free(unformatted_json);
	cJSON_Delete(add_json);
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(events.size() == 1);
	check_no_error();

	cJSON *json = create_set_without_path();
	unformatted_json = cJSON_PrintUnformatted(json);
	ret = parse_message(unformatted_json, strlen(unformatted_json), &set_peer);
	cjet_free(unformatted_json);
	cJSON_Delete(json);
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(events.size() == 1);
	check_invalid_params_error();
}

BOOST_FIXTURE_TEST_CASE(set_without_params, F)
{
	cJSON *json = create_set_without_params();
	char *unformatted_json = cJSON_PrintUnformatted(json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), &p);
	cjet_free(unformatted_json);
	cJSON_Delete(json);
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(events.size() == 1);
	check_invalid_params_error();
}

/*
 * This test is main mainly to check freeing all resources with valgrind
 *
 */
BOOST_FIXTURE_TEST_CASE(set_without_path_and_no_id, F)
{
	cJSON *json = create_set_without_path_and_no_id();
	char *unformatted_json = cJSON_PrintUnformatted(json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), &p);
	cjet_free(unformatted_json);
	cJSON_Delete(json);
	BOOST_CHECK(ret == 0);
}

BOOST_FIXTURE_TEST_CASE(set_without_value, F)
{
	cJSON *json = create_set_without_value();
	char *unformatted_json = cJSON_PrintUnformatted(json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), &p);
	cjet_free(unformatted_json);
	cJSON_Delete(json);
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(events.size() == 1);
	check_invalid_params_error();
}

BOOST_FIXTURE_TEST_CASE(correct_info, F)
{
	cJSON *json = create_correct_info_method();
	char *unformatted_json = cJSON_PrintUnformatted(json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), &p);
	cjet_free(unformatted_json);
	cJSON_Delete(json);
	BOOST_CHECK(ret == 0);
}

BOOST_FIXTURE_TEST_CASE(correct_info_without_params, F)
{
	cJSON *json = create_correct_info_method_without_params();
	char *unformatted_json = cJSON_PrintUnformatted(json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), &p);
	cjet_free(unformatted_json);
	cJSON_Delete(json);
	BOOST_CHECK(ret == 0);
	BOOST_CHECK(events.size() == 1);
	check_no_error();
}
