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
#include <list>

#include "compiler.h"
#include "element.h"
#include "json/cJSON.h"
#include "parse.h"
#include "peer.h"
#include "router.h"
#include "table.h"

static char send_buffer[100000];

static std::list<struct io_event *> timer_evs;

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

int send_message(const struct peer *p, char *rendered, size_t len)
{
	(void)p;
	memcpy(send_buffer, rendered, len);
	return 0;
}

static struct element *get_state(const char *path)
{
	return (struct element *)element_table_get(path);
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

static cJSON *create_set_request(const char *request_id, const char *path)
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

static cJSON *create_set_request_with_timeout(const char *request_id, const char *path, double timeout_s)
{
	cJSON *set_request = create_set_request(request_id, path);
	cJSON *params = cJSON_GetObjectItem(set_request, "params");
	cJSON_AddNumberToObject(params, "timeout", timeout_s);
	return set_request;
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

static enum eventloop_return fake_add(const void *this_ptr, const struct io_event *ev)
{
	(void)this_ptr;
	timer_evs.push_back((struct io_event *)ev);
	return EL_CONTINUE_LOOP;
}

static void fake_remove(const void *this_ptr, const struct io_event *ev)
{
	(void)this_ptr;
	(void)ev;
	timer_evs.remove((struct io_event *)ev);
	return;
}

static struct eventloop loop;

struct F {
	F()
	{
		timer_evs.clear();
		loop.this_ptr = NULL;
		loop.init = NULL;
		loop.destroy = NULL;
		loop.run = NULL;
		loop.add = fake_add;
		loop.remove = fake_remove;

		init_parser();
		element_hashtable_create();
		init_peer(&p, false, &loop);
		p.send_message = send_message;
		init_peer(&owner_peer, false, &loop);
		owner_peer.send_message = send_message;
		init_peer(&set_peer, false, &loop);
		set_peer.send_message = send_message;
	}

	~F()
	{
		free_peer_resources(&set_peer);
		free_peer_resources(&owner_peer);
		free_peer_resources(&p);
		element_hashtable_delete();
	}

	struct peer p;
	struct peer owner_peer;
	struct peer set_peer;
};

static void check_response(cJSON *json, const char *id)
{
	cJSON *response_id = cJSON_GetObjectItem(json, "id");
	BOOST_CHECK((response_id != NULL) &&
				 (response_id->type == cJSON_String) &&
				 (strcmp(response_id->valuestring, id) == 0));
	cJSON *result = cJSON_GetObjectItem(json, "result");
	BOOST_CHECK(result != NULL);
}

static void check_internal_error(const cJSON *response)
{
	const cJSON *error = cJSON_GetObjectItem(response, "error");

	cJSON *code = cJSON_GetObjectItem(error, "code");
	if (code != NULL) {
		BOOST_CHECK(code->type == cJSON_Number);
		BOOST_CHECK(code->valueint == -32603);
	} else {
		BOOST_FAIL("No code object!");
	}

	cJSON *message = cJSON_GetObjectItem(error, "message");
	if (message != NULL) {
		BOOST_CHECK(message->type == cJSON_String);
		BOOST_CHECK(strcmp(message->valuestring, "Internal error") == 0);
	} else {
		BOOST_FAIL("No message object!");
	}
}

static void check_invalid_params(const cJSON *response)
{
	const cJSON *error = cJSON_GetObjectItem(response, "error");

	const cJSON *code = cJSON_GetObjectItem(error, "code");
	if (code != NULL) {
		BOOST_CHECK(code->type == cJSON_Number);
		BOOST_CHECK(code->valueint == -32602);
	} else {
		BOOST_FAIL("No code object!");
	}

	const cJSON *message = cJSON_GetObjectItem(error, "message");
	if (message != NULL) {
		BOOST_CHECK(message->type == cJSON_String);
		BOOST_CHECK(strcmp(message->valuestring, "Invalid params") == 0);
	} else {
		BOOST_FAIL("No message object!");
	}
}

static cJSON *create_add(const char *path)
{
	cJSON *params = cJSON_CreateObject();
	BOOST_REQUIRE(params != NULL);
	cJSON_AddStringToObject(params, "path", path);
	cJSON_AddItemToObject(params, "value", cJSON_CreateNumber(1234));

	cJSON *root = cJSON_CreateObject();
	cJSON_AddItemToObject(root, "params", params);
	cJSON_AddStringToObject(root, "id", "add_request_1");
	cJSON_AddStringToObject(root, "method", "add");
	return root;
}

static cJSON *create_add_method(const char *path)
{
	cJSON *params = cJSON_CreateObject();
	BOOST_REQUIRE(params != NULL);
	cJSON_AddStringToObject(params, "path", path);

	cJSON *root = cJSON_CreateObject();
	cJSON_AddItemToObject(root, "params", params);
	cJSON_AddStringToObject(root, "id", "add_request_1");
	cJSON_AddStringToObject(root, "method", "add");
	return root;
}

static cJSON *create_change(const char *path)
{
	cJSON *params = cJSON_CreateObject();
	BOOST_REQUIRE(params != NULL);
	cJSON_AddStringToObject(params, "path", path);
	cJSON_AddItemToObject(params, "value", cJSON_CreateNumber(4321));

	cJSON *root = cJSON_CreateObject();
	cJSON_AddItemToObject(root, "params", params);
	cJSON_AddStringToObject(root, "id", "change_request_1");
	cJSON_AddStringToObject(root, "method", "change");
	return root;
}

static bool response_is_error(const cJSON *response)
{
	const cJSON *error = cJSON_GetObjectItem(response, "error");
	return (error != NULL);
}

BOOST_FIXTURE_TEST_CASE(add_state_existing_method, F)
{
	const char path[] = "/foo/bar/";

	cJSON *request = create_add(path);

	cJSON *response = add_element_to_peer(&owner_peer, request);
	BOOST_REQUIRE_MESSAGE(response != NULL, "add_element_to_peer() had no response!");
	BOOST_CHECK_MESSAGE(!response_is_error(response), "add_element_to_peer() failed!");
	cJSON_Delete(response);

	response = add_element_to_peer(&owner_peer, request);
	BOOST_REQUIRE_MESSAGE(response != NULL, "add_element_to_peer() had no response!");
	check_invalid_params(response);
	cJSON_Delete(response);
	cJSON_Delete(request);
}

BOOST_FIXTURE_TEST_CASE(add_state, F)
{
	const char path[] = "/foo/bar/";

	cJSON *request = create_add(path);
	cJSON *params = cJSON_GetObjectItem(request, "params");
	cJSON *json_path = cJSON_GetObjectItem(params, "path");
	cJSON *value = cJSON_GetObjectItem(params, "value");

	cJSON *response = add_element_to_peer(&p, request);
	BOOST_REQUIRE_MESSAGE(response != NULL, "add_element_to_peer() had no response!");
	BOOST_CHECK_MESSAGE(!response_is_error(response), "add_element_to_peer() failed!");
	cJSON_Delete(response);

	struct element *e = get_state(json_path->valuestring);
	BOOST_CHECK(e->value->valueint == value->valueint);
	cJSON_Delete(request);
}

BOOST_FIXTURE_TEST_CASE(add_duplicate_state, F)
{
	const char path[] = "/foo/bar/";

	cJSON *request = create_add(path);

	cJSON *response = add_element_to_peer(&p, request);
	BOOST_REQUIRE_MESSAGE(response != NULL, "add_element_to_peer() had no response!");
	BOOST_CHECK_MESSAGE(!response_is_error(response), "add_element_to_peer() failed!");
	cJSON_Delete(response);

	response = add_element_to_peer(&p, request);
	BOOST_REQUIRE(response != NULL);
	check_invalid_params(response);
	cJSON_Delete(response);
	cJSON_Delete(request);
}

BOOST_FIXTURE_TEST_CASE(delete_single_state, F)
{
	const char path[] = "/foo/bar/";

	cJSON *request = create_add(path);

	cJSON *response = add_element_to_peer(&p, request);
	BOOST_REQUIRE_MESSAGE(response != NULL, "add_element_to_peer() had no response!");
	BOOST_CHECK_MESSAGE(!response_is_error(response), "add_element_to_peer() failed!");
	cJSON_Delete(response);

	response = remove_element_from_peer(&p, request);
	BOOST_REQUIRE_MESSAGE(response != NULL, "remove_element_from_peer() had no response!");
	BOOST_CHECK_MESSAGE(!response_is_error(response), "remove_element_from_peer() failed!");
	cJSON_Delete(request);
	cJSON_Delete(response);
}

BOOST_FIXTURE_TEST_CASE(delete_nonexisting_state, F)
{
	const char path[] = "/foo/bar/";

	cJSON *request = create_add(path);

	cJSON *response = remove_element_from_peer(&p, request);
	BOOST_REQUIRE_MESSAGE(response != NULL, "remove_element_from_peer() had no response!");
	BOOST_CHECK_MESSAGE(response_is_error(response), "removing non-existant state did not fail!");
	cJSON_Delete(request);
	cJSON_Delete(response);
}

BOOST_FIXTURE_TEST_CASE(double_free_state, F)
{
	const char path[] = "/foo/bar/";

	cJSON *request = create_add(path);

	cJSON *response = add_element_to_peer(&p, request);
	BOOST_REQUIRE_MESSAGE(response != NULL, "add_element_to_peer() had no response!");
	BOOST_CHECK_MESSAGE(!response_is_error(response), "add_element_to_peer() failed!");
	cJSON_Delete(response);

	response = remove_element_from_peer(&p, request);
	BOOST_REQUIRE_MESSAGE(response != NULL, "remove_element_from_peer() had no response!");
	BOOST_CHECK_MESSAGE(!response_is_error(response), "removing state failed!");
	cJSON_Delete(response);

	response = remove_element_from_peer(&p, request);
	BOOST_REQUIRE_MESSAGE(response != NULL, "remove_element_from_peer() had no response!");
	BOOST_CHECK_MESSAGE(response_is_error(response), "double free of state did not fail!");
	cJSON_Delete(request);
	cJSON_Delete(response);
}

BOOST_FIXTURE_TEST_CASE(change, F)
{
	const char path[] = "/foo/bar/";

	cJSON *request = create_add(path);

	cJSON *response = add_element_to_peer(&p, request);
	BOOST_REQUIRE_MESSAGE(response != NULL, "add_element_to_peer() had no response!");
	BOOST_CHECK_MESSAGE(!response_is_error(response), "add_element_to_peer() failed!");
	cJSON_Delete(response);
	cJSON_Delete(request);

	request = create_change(path);
	cJSON *params = cJSON_GetObjectItem(request, "params");
	cJSON *json_path = cJSON_GetObjectItem(params, "path");
	cJSON *new_value = cJSON_GetObjectItem(params, "value");

	response = change_state(&p, request);
	BOOST_REQUIRE_MESSAGE(response != NULL, "change_state() had no response!");
	BOOST_CHECK_MESSAGE(!response_is_error(response), "change_state() failed!");

	struct element *e = get_state(json_path->valuestring);
	BOOST_CHECK(e->value->valueint == new_value->valueint);
	cJSON_Delete(request);
	cJSON_Delete(response);
}

BOOST_FIXTURE_TEST_CASE(change_no_params, F)
{
	const char path[] = "/foo/bar/";

	cJSON *request = create_add(path);

	cJSON *response = add_element_to_peer(&p, request);
	BOOST_REQUIRE_MESSAGE(response != NULL, "add_element_to_peer() had no response!");
	BOOST_CHECK_MESSAGE(!response_is_error(response), "add_element_to_peer() failed!");
	cJSON_Delete(response);
	cJSON_Delete(request);

	request = cJSON_CreateObject();
	cJSON_AddStringToObject(request, "id", "change_request_1");
	cJSON_AddStringToObject(request, "method", "change");

	response = change_state(&p, request);
	BOOST_REQUIRE_MESSAGE(response != NULL, "change_state() had no response!");
	BOOST_CHECK_MESSAGE(response_is_error(response), "change_state() with no params did not fail!");

	cJSON_Delete(request);
	cJSON_Delete(response);
}

BOOST_FIXTURE_TEST_CASE(change_not_by_owner, F)
{
	const char path[] = "/foo/bar/";

	cJSON *request = create_add(path);

	cJSON *response = add_element_to_peer(&p, request);
	BOOST_REQUIRE_MESSAGE(response != NULL, "add_element_to_peer() had no response!");
	BOOST_CHECK_MESSAGE(!response_is_error(response), "add_element_to_peer() failed!");
	cJSON_Delete(response);
	cJSON_Delete(request);

	request = create_change(path);

	response = change_state(&set_peer, request);
	BOOST_REQUIRE_MESSAGE(response != NULL, "change_state() had no response!");
	BOOST_CHECK_MESSAGE(response_is_error(response), "non-owner change did not fail!");
	cJSON_Delete(response);
	cJSON_Delete(request);
}

BOOST_FIXTURE_TEST_CASE(change_wrong_path, F)
{
	const char path[] = "/foo/bar/";

	cJSON *request = create_add(path);

	cJSON *response = add_element_to_peer(&p, request);
	BOOST_REQUIRE_MESSAGE(response != NULL, "add_element_to_peer() had no response!");
	BOOST_CHECK_MESSAGE(!response_is_error(response), "add_element_to_peer() failed!");
	cJSON_Delete(response);
	cJSON_Delete(request);

	request = create_change("/bar/foo/");

	response = change_state(&p, request);
	BOOST_REQUIRE_MESSAGE(response != NULL, "change_state() had no response!");
	BOOST_CHECK_MESSAGE(response_is_error(response), "wrong path change did not fail!");
	check_invalid_params(response);
	cJSON_Delete(response);
	cJSON_Delete(request);
}

BOOST_FIXTURE_TEST_CASE(change_on_method, F)
{
	const char path[] = "/foo/bar/";

	cJSON *request = create_add_method(path);

	cJSON *response = add_element_to_peer(&p, request);
	BOOST_REQUIRE_MESSAGE(response != NULL, "add_element_to_peer() had no response!");
	BOOST_CHECK_MESSAGE(!response_is_error(response), "add_element_to_peer() failed!");
	cJSON_Delete(response);
	cJSON_Delete(request);

	request = create_change(path);

	response = change_state(&p, request);
	BOOST_REQUIRE_MESSAGE(response != NULL, "change_state() had no response!");
	check_invalid_params(response);
	cJSON_Delete(response);
	cJSON_Delete(request);
}

BOOST_FIXTURE_TEST_CASE(set_on_method, F)
{
	const char path[] = "/foo/bar";
	cJSON *request = create_add_method(path);

	cJSON *response = add_element_to_peer(&p, request);
	BOOST_REQUIRE_MESSAGE(response != NULL, "add_element_to_peer() had no response!");
	BOOST_CHECK_MESSAGE(!response_is_error(response), "add_element_to_peer() failed!");
	cJSON_Delete(response);
	cJSON_Delete(request);

	cJSON *set_request = create_set_request("request1", path);
	response = set_or_call(&set_peer, set_request, STATE);
	cJSON_Delete(set_request);
	BOOST_REQUIRE_MESSAGE(response != NULL, "change_state() had no response!");
	check_invalid_params(response);
	cJSON_Delete(response);
}

BOOST_FIXTURE_TEST_CASE(set_on_fetchonly, F)
{
	const char path[] = "/foo/bar";
	cJSON *request = create_add(path);
	cJSON *params = cJSON_GetObjectItem(request, "params");
	cJSON_AddItemToObject(params, "fetchOnly", cJSON_CreateTrue());

	cJSON *response = add_element_to_peer(&p, request);
	BOOST_REQUIRE_MESSAGE(response != NULL, "add_element_to_peer() had no response!");
	BOOST_CHECK_MESSAGE(!response_is_error(response), "add_element_to_peer() failed!");
	cJSON_Delete(response);
	cJSON_Delete(request);

	cJSON *set_request = create_set_request("request1", path);
	response = set_or_call(&set_peer, set_request, STATE);
	cJSON_Delete(set_request);
	BOOST_REQUIRE_MESSAGE(response != NULL, "set_or_call() had no response!");
	check_invalid_params(response);
	cJSON_Delete(response);
}

BOOST_FIXTURE_TEST_CASE(set, F)
{
	const char path[] = "/foo/bar/";
	cJSON *request = create_add(path);

	cJSON *response = add_element_to_peer(&p, request);
	BOOST_REQUIRE_MESSAGE(response != NULL, "add_element_to_peer() had no response!");
	BOOST_CHECK_MESSAGE(!response_is_error(response), "add_element_to_peer() failed!");
	cJSON_Delete(response);
	cJSON_Delete(request);

	cJSON *set_request = create_set_request("request1", path);
	response = set_or_call(&set_peer, set_request, STATE);
	cJSON_Delete(set_request);
	BOOST_CHECK_MESSAGE(response == NULL, "There must be no response when calling set/call");
	BOOST_CHECK_MESSAGE(timer_evs.size() == 1, "No timer_ev was registered!");

	cJSON *routed_message = parse_send_buffer();
	response = create_response_from_message(routed_message);
	cJSON *result = get_result_from_response(response);

	int ret = handle_routing_response(response, result, "result", &p);
	BOOST_CHECK(ret == 0);
	BOOST_CHECK_MESSAGE(timer_evs.size() == 0, "timer_ev was not deregistered!");

	cJSON_Delete(routed_message);
	cJSON_Delete(response);
}

BOOST_FIXTURE_TEST_CASE(set_with_correct_timeout, F)
{
	double timeout_s = 2.22;
	const char path[] = "/foo/bar/";
	cJSON *request = create_add(path);

	cJSON *response = add_element_to_peer(&p, request);
	BOOST_REQUIRE_MESSAGE(response != NULL, "add_element_to_peer() had no response!");
	BOOST_CHECK_MESSAGE(!response_is_error(response), "add_element_to_peer() failed!");
	cJSON_Delete(response);
	cJSON_Delete(request);

	cJSON *set_request = create_set_request_with_timeout("request1", path, timeout_s);
	response = set_or_call(&set_peer, set_request, STATE);
	cJSON_Delete(set_request);
	BOOST_CHECK_MESSAGE(response == NULL, "There must be no response when calling set/call");
	BOOST_CHECK_MESSAGE(timer_evs.size() == 1, "No timer_ev was registered!");

	cJSON *routed_message = parse_send_buffer();
	response = create_response_from_message(routed_message);
	cJSON *result = get_result_from_response(response);

	int ret = handle_routing_response(response, result, "result", &p);
	BOOST_CHECK(ret == 0);
	BOOST_CHECK_MESSAGE(timer_evs.size() == 0, "timer_ev was not deregistered!");

	cJSON_Delete(routed_message);
	cJSON_Delete(response);
}

BOOST_FIXTURE_TEST_CASE(set_with_negative_timeout, F)
{
	double timeout_s = -2.22;
	const char path[] = "/foo/bar/";
	cJSON *request = create_add(path);

	cJSON *response = add_element_to_peer(&p, request);
	BOOST_REQUIRE_MESSAGE(response != NULL, "add_element_to_peer() had no response!");
	BOOST_CHECK_MESSAGE(!response_is_error(response), "add_element_to_peer() failed!");
	cJSON_Delete(response);
	cJSON_Delete(request);

	cJSON *set_request = create_set_request_with_timeout("request1", path, timeout_s);
	response = set_or_call(&set_peer, set_request, STATE);
	BOOST_REQUIRE_MESSAGE(response != NULL, "set_or_call() had no response!");
	check_invalid_params(response);
	cJSON_Delete(set_request);
	cJSON_Delete(response);
	BOOST_CHECK_MESSAGE(response != NULL, "no error object created for set request with negative timeout");
	BOOST_CHECK_MESSAGE(timer_evs.size() == 0, "timer_ev was registered for set request with negative timeout!");

}

BOOST_FIXTURE_TEST_CASE(set_with_illegal_timeout_object, F)
{
	const char path[] = "/foo/bar/";
	cJSON *request = create_add(path);

	cJSON *response = add_element_to_peer(&p, request);
	BOOST_REQUIRE_MESSAGE(response != NULL, "add_element_to_peer() had no response!");
	BOOST_CHECK_MESSAGE(!response_is_error(response), "add_element_to_peer() failed!");
	cJSON_Delete(response);
	cJSON_Delete(request);

	cJSON *set_request = create_set_request("request1", path);
	cJSON *params = cJSON_GetObjectItem(set_request, "params");
	cJSON_AddStringToObject(params, "timeout", "hello");
	response = set_or_call(&set_peer, set_request, STATE);
	BOOST_REQUIRE_MESSAGE(response != NULL, "set_or_call() had no response!");
	check_invalid_params(response);
	cJSON_Delete(set_request);
	BOOST_CHECK_MESSAGE((response != NULL) && (response_is_error(response)), "no error object created for set request with negative timeout");
	BOOST_CHECK_MESSAGE(timer_evs.size() == 0, "timer_ev was registered for set request with illegal timeout object!");
	cJSON_Delete(response);
}

BOOST_FIXTURE_TEST_CASE(set_wrong_path, F)
{
	const char path[] = "/foo/bar/";
	cJSON *request = create_add(path);

	cJSON *response = add_element_to_peer(&p, request);
	BOOST_REQUIRE_MESSAGE(response != NULL, "add_element_to_peer() had no response!");
	BOOST_CHECK_MESSAGE(!response_is_error(response), "add_element_to_peer() failed!");
	cJSON_Delete(response);
	cJSON_Delete(request);

	const char set_path[] = "/bar/foo/";
	cJSON *set_request = create_set_request("request1", set_path);
	response = set_or_call(&set_peer, set_request, STATE);
	cJSON_Delete(set_request);
	BOOST_CHECK_MESSAGE((response != NULL) && (response_is_error(response)), "no error object created for set request with negative timeout");
	cJSON_Delete(response);
}

BOOST_FIXTURE_TEST_CASE(set_without_id_without_response, F)
{
	const char path[] = "/foo/bar/";
	cJSON *request = create_add(path);

	cJSON *response = add_element_to_peer(&p, request);
	BOOST_REQUIRE_MESSAGE(response != NULL, "add_element_to_peer() had no response!");
	BOOST_CHECK_MESSAGE(!response_is_error(response), "add_element_to_peer() failed!");
	cJSON_Delete(request);
	cJSON_Delete(response);

	cJSON *set_request = create_set_request(NULL, path);
	response = set_or_call(&set_peer, set_request, STATE);
	cJSON_Delete(set_request);
	BOOST_CHECK_MESSAGE(response == NULL, "There must be no response when calling set/call");
	cJSON_Delete(response);
}

BOOST_FIXTURE_TEST_CASE(set_wrong_id_type, F)
{
	const char path[] = "/foo/bar/";
	cJSON *request = create_add(path);

	cJSON *response = add_element_to_peer(&p, request);
	BOOST_REQUIRE_MESSAGE(response != NULL, "add_element_to_peer() had no response!");
	BOOST_CHECK_MESSAGE(!response_is_error(response), "add_element_to_peer() failed!");
	cJSON_Delete(request);
	cJSON_Delete(response);

	cJSON *set_request = cJSON_CreateObject();
	cJSON_AddStringToObject(set_request, "method", "set");
	cJSON_AddTrueToObject(set_request, "id");

	cJSON *params = cJSON_CreateObject();
	cJSON_AddStringToObject(params, "path", path);
	cJSON *new_value = cJSON_CreateNumber(4321);
	cJSON_AddItemToObject(params, "value", new_value);
	cJSON_AddItemToObject(set_request, "params", params);

	response = set_or_call(&set_peer, set_request, STATE);
	cJSON_Delete(set_request);

	BOOST_CHECK_MESSAGE(response == NULL, "Got response despite wrong request id type!");
	cJSON_Delete(response);
}

BOOST_FIXTURE_TEST_CASE(set_without_id_with_response, F)
{
	const char path[] = "/foo/bar/";
	cJSON *request = create_add(path);

	cJSON *response = add_element_to_peer(&p, request);
	BOOST_REQUIRE_MESSAGE(response != NULL, "add_element_to_peer() had no response!");
	BOOST_CHECK_MESSAGE(!response_is_error(response), "add_element_to_peer() failed!");
	cJSON_Delete(response);
	cJSON_Delete(request);

	cJSON *set_request = create_set_request(NULL, path);
	response = set_or_call(&set_peer, set_request, STATE);
	cJSON_Delete(set_request);
	BOOST_CHECK_MESSAGE(response == NULL, "There must be no response when calling set/call");

	cJSON *routed_message = parse_send_buffer();
	response = create_response_from_message(routed_message);
	cJSON *result = get_result_from_response(response);

	int ret = handle_routing_response(response, result, "result", &p);
	BOOST_CHECK(ret == 0);

	cJSON_Delete(routed_message);
	cJSON_Delete(response);
}

BOOST_FIXTURE_TEST_CASE(set_with_timeout_before_response, F)
{
	const char path[] = "/foo/bar/";
	cJSON *request = create_add(path);

	cJSON *response = add_element_to_peer(&p, request);
	BOOST_REQUIRE_MESSAGE(response != NULL, "add_element_to_peer() had no response!");
	BOOST_CHECK_MESSAGE(!response_is_error(response), "add_element_to_peer() failed!");
	cJSON_Delete(response);
	cJSON_Delete(request);

	cJSON *set_request = create_set_request("request1", path);
	response = set_or_call(&set_peer, set_request, STATE);
	cJSON_Delete(set_request);
	BOOST_CHECK_MESSAGE(response == NULL, "There must be no response when calling set/call");

	cJSON *routed_message = parse_send_buffer();
	response = create_response_from_message(routed_message);
	cJSON *result = get_result_from_response(response);

	BOOST_REQUIRE_MESSAGE(timer_evs.size() == 1, "No timer ev was registered!");
	struct io_event *timer_ev = timer_evs.front();
	enum eventloop_return el_ret = timer_ev->read_function(timer_ev);
	BOOST_CHECK_MESSAGE(el_ret == EL_CONTINUE_LOOP, "timer read function did not returned EL_CONTINUE_LOOP");
	BOOST_REQUIRE_MESSAGE(timer_evs.size() == 0, "timer was not remove from eventloop!");
	cJSON *error_message = parse_send_buffer();
	BOOST_REQUIRE_MESSAGE(error_message != NULL, "Error message does not contain an error object!");
	check_internal_error(error_message);
	cJSON_Delete(error_message);

	int ret = handle_routing_response(response, result, "result", &p);
	BOOST_CHECK_MESSAGE(ret == 0, "Response after timeout not silently ignored!");

	cJSON_Delete(routed_message);
	cJSON_Delete(response);
}

BOOST_FIXTURE_TEST_CASE(set_with_timeout_after_response, F)
{
	const char path[] = "/foo/bar/";
	const char request_id[] = "request1";
	cJSON *request = create_add(path);

	cJSON *response = add_element_to_peer(&p, request);
	BOOST_REQUIRE_MESSAGE(response != NULL, "add_element_to_peer() had no response!");
	BOOST_CHECK_MESSAGE(!response_is_error(response), "add_element_to_peer() failed!");
	cJSON_Delete(response);
	cJSON_Delete(request);

	cJSON *set_request = create_set_request(request_id, path);
	response = set_or_call(&set_peer, set_request, STATE);
	cJSON_Delete(set_request);
	BOOST_CHECK_MESSAGE(response == NULL, "There must be no response when calling set/call");

	cJSON *routed_message = parse_send_buffer();
	response = create_response_from_message(routed_message);
	cJSON *result = get_result_from_response(response);
	cJSON_Delete(routed_message);

	int ret = handle_routing_response(response, result, "result", &p);
	BOOST_CHECK_MESSAGE(ret == 0, "Response after timeout not silently ignored!");
	cJSON_Delete(response);

	cJSON *error_message = parse_send_buffer();
	BOOST_REQUIRE_MESSAGE(error_message != NULL, "Error message does not contain an error object!");
	check_response(error_message, request_id);
	cJSON_Delete(error_message);

	//BOOST_REQUIRE_MESSAGE(timer_evs.size() == 1, "No timer ev was registered!");
	//struct io_event *timer_ev = timer_evs.front();
	//enum eventloop_return el_ret = timer_ev->read_function(timer_ev);
	//BOOST_CHECK_MESSAGE(el_ret == EL_CONTINUE_LOOP, "timer read function did not returned EL_CONTINUE_LOOP");
	//BOOST_REQUIRE_MESSAGE(timer_evs.size() == 0, "timer was not remove from eventloop!");
	//cJSON *error_message = parse_send_buffer();
	//BOOST_REQUIRE_MESSAGE(error_message != NULL, "Error message does not contain an error object!");
	//check_internal_error(error_message);
	//cJSON_Delete(error_message);


}

BOOST_FIXTURE_TEST_CASE(set_with_destroy_before_response, F)
{
	struct peer setter_peer;
	init_peer(&setter_peer, false, &loop);
	setter_peer.send_message = send_message;

	const char path[] = "/foo/bar/";
	cJSON *request = create_add(path);

	cJSON *response = add_element_to_peer(&p, request);
	BOOST_REQUIRE_MESSAGE(response != NULL, "add_element_to_peer() had no response!");
	BOOST_CHECK_MESSAGE(!response_is_error(response), "add_element_to_peer() failed!");
	cJSON_Delete(response);
	cJSON_Delete(request);

	cJSON *set_request = create_set_request("request1", path);
	response = set_or_call(&setter_peer, set_request, STATE);
	cJSON_Delete(set_request);
	BOOST_CHECK_MESSAGE(response == NULL, "There must be no response when calling set/call");

	cJSON *routed_message = parse_send_buffer();
	response = create_response_from_message(routed_message);
	cJSON *result = get_result_from_response(response);

	free_peer_resources(&setter_peer);

	int ret = handle_routing_response(response, result, "result", &p);
	BOOST_CHECK_MESSAGE(ret == 0, "Response after timeout/destroy not silently ignored!");

	cJSON_Delete(routed_message);
	cJSON_Delete(response);
}

BOOST_FIXTURE_TEST_CASE(second_set_before_first_response, F)
{
	double timeout_s = 2.22;
	const char path[] = "/foo/bar/";
	cJSON *request = create_add(path);

	cJSON *response = add_element_to_peer(&p, request);
	BOOST_REQUIRE_MESSAGE(response != NULL, "add_element_to_peer() had no response!");
	BOOST_CHECK_MESSAGE(!response_is_error(response), "add_element_to_peer() failed!");
	cJSON_Delete(response);
	cJSON_Delete(request);

	cJSON *set_request1 = create_set_request_with_timeout("request1", path, timeout_s);
	response = set_or_call(&set_peer, set_request1, STATE);
	cJSON_Delete(set_request1);
	BOOST_CHECK_MESSAGE(response == NULL, "There must be no response when calling set/call");

	cJSON *routed_message1 = parse_send_buffer();
	cJSON *response1 = create_response_from_message(routed_message1);
	cJSON *result1 = get_result_from_response(response1);

	cJSON *set_request2 = create_set_request_with_timeout("request2", path, timeout_s);
	response = set_or_call(&set_peer, set_request2, STATE);
	cJSON_Delete(set_request2);
	BOOST_CHECK_MESSAGE(response == NULL, "There must be no response when calling set/call");

	cJSON *routed_message2 = parse_send_buffer();
	cJSON *response2 = create_response_from_message(routed_message1);
	cJSON *result2 = get_result_from_response(response1);

	int ret = handle_routing_response(response1, result1, "result", &p);
	BOOST_CHECK(ret == 0);
	cJSON_Delete(routed_message1);
	cJSON_Delete(response1);

	ret = handle_routing_response(response2, result2, "result", &p);
	BOOST_CHECK(ret == 0);
	cJSON_Delete(routed_message2);
	cJSON_Delete(response2);
}

BOOST_FIXTURE_TEST_CASE(two_sets_with_first_timeout, F)
{
	double timeout_s = 2.22;
	const char path[] = "/foo/bar/";
	cJSON *request = create_add(path);

	cJSON *response = add_element_to_peer(&p, request);
	BOOST_REQUIRE_MESSAGE(response != NULL, "add_element_to_peer() had no response!");
	BOOST_CHECK_MESSAGE(!response_is_error(response), "add_element_to_peer() failed!");
	cJSON_Delete(response);
	cJSON_Delete(request);

	cJSON *set_request1 = create_set_request_with_timeout("request1", path, timeout_s);
	response = set_or_call(&set_peer, set_request1, STATE);
	cJSON_Delete(set_request1);
	BOOST_CHECK_MESSAGE(response == NULL, "There must be no response when calling set/call");

	cJSON *routed_message1 = parse_send_buffer();
	cJSON *response1 = create_response_from_message(routed_message1);
	cJSON *result1 = get_result_from_response(response1);

	BOOST_REQUIRE_MESSAGE(timer_evs.size() == 1, "No timer ev was registered!");
	struct io_event *timer_ev = timer_evs.front();
	enum eventloop_return el_ret = timer_ev->read_function(timer_ev);
	BOOST_CHECK_MESSAGE(el_ret == EL_CONTINUE_LOOP, "timer read function did not returned EL_CONTINUE_LOOP");
	BOOST_REQUIRE_MESSAGE(timer_evs.size() == 0, "timer was not remove from eventloop!");

	cJSON *error_message = parse_send_buffer();
	BOOST_REQUIRE_MESSAGE(error_message != NULL, "Error message does not contain an error object!");
	check_internal_error(error_message);
	cJSON_Delete(error_message);

	cJSON *set_request2 = create_set_request_with_timeout("request2", path, timeout_s);
	response = set_or_call(&set_peer, set_request2, STATE);
	cJSON_Delete(set_request2);
	BOOST_CHECK_MESSAGE(response == NULL, "There must be no response when calling set/call");

	cJSON *routed_message2 = parse_send_buffer();
	cJSON *response2 = create_response_from_message(routed_message1);
	cJSON *result2 = get_result_from_response(response1);

	int ret = handle_routing_response(response1, result1, "result", &p);
	BOOST_CHECK_MESSAGE(ret == 0, "Response after timeout not silently ignored!");
	cJSON_Delete(routed_message1);
	cJSON_Delete(response1);

	ret = handle_routing_response(response2, result2, "result", &p);
	BOOST_CHECK(ret == 0);
	cJSON_Delete(routed_message2);
	cJSON_Delete(response2);
}

BOOST_FIXTURE_TEST_CASE(two_sets_all_timeout, F)
{
	double timeout_s = 2.22;
	const char path[] = "/foo/bar/";
	cJSON *request = create_add(path);

	cJSON *response = add_element_to_peer(&p, request);
	BOOST_REQUIRE_MESSAGE(response != NULL, "add_element_to_peer() had no response!");
	BOOST_CHECK_MESSAGE(!response_is_error(response), "add_element_to_peer() failed!");
	cJSON_Delete(response);
	cJSON_Delete(request);

	cJSON *set_request1 = create_set_request_with_timeout("request1", path, timeout_s);
	response = set_or_call(&set_peer, set_request1, STATE);
	cJSON_Delete(set_request1);
	BOOST_CHECK_MESSAGE(response == NULL, "There must be no response when calling set/call");

	cJSON *routed_message1 = parse_send_buffer();
	cJSON *response1 = create_response_from_message(routed_message1);
	cJSON *result1 = get_result_from_response(response1);

	cJSON *set_request2 = create_set_request_with_timeout("request2", path, timeout_s);
	response = set_or_call(&set_peer, set_request2, STATE);
	cJSON_Delete(set_request2);
	BOOST_CHECK_MESSAGE(response == NULL, "There must be no response when calling set/call");

	cJSON *routed_message2 = parse_send_buffer();
	cJSON *response2 = create_response_from_message(routed_message1);
	cJSON *result2 = get_result_from_response(response1);

	BOOST_REQUIRE_MESSAGE(timer_evs.size() == 2, "No timer ev was registered!");
	struct io_event *timer_ev = timer_evs.front();
	enum eventloop_return el_ret = timer_ev->read_function(timer_ev);
	BOOST_CHECK_MESSAGE(el_ret == EL_CONTINUE_LOOP, "timer read function did not returned EL_CONTINUE_LOOP");
	BOOST_REQUIRE_MESSAGE(timer_evs.size() == 1, "timer was not remove from eventloop!");

	cJSON *error_message = parse_send_buffer();
	BOOST_REQUIRE_MESSAGE(error_message != NULL, "Error message does not contain an error object!");
	check_internal_error(error_message);
	cJSON_Delete(error_message);

	timer_ev = timer_evs.front();
	el_ret = timer_ev->read_function(timer_ev);
	BOOST_CHECK_MESSAGE(el_ret == EL_CONTINUE_LOOP, "timer read function did not returned EL_CONTINUE_LOOP");
	BOOST_REQUIRE_MESSAGE(timer_evs.size() == 0, "timer was not remove from eventloop!");

	error_message = parse_send_buffer();
	BOOST_REQUIRE_MESSAGE(error_message != NULL, "Error message does not contain an error object!");
	check_internal_error(error_message);
	cJSON_Delete(error_message);

	int ret = handle_routing_response(response1, result1, "result", &p);
	BOOST_CHECK_MESSAGE(ret == 0, "Response after timeout not silently ignored!");
	cJSON_Delete(routed_message1);
	cJSON_Delete(response1);

	ret = handle_routing_response(response2, result2, "result", &p);
	BOOST_CHECK(ret == 0);
	cJSON_Delete(routed_message2);
	cJSON_Delete(response2);
}
