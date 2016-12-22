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
#include "parse.h"
#include "peer.h"
#include "router.h"
#include "element.h"
#include "table.h"

static const char *method_no_args_path = "/method_no_args/";

static const int INVALID_PARAMS_ERROR = -32602;

extern "C" {
	ssize_t socket_read(socket_type sock, void *buf, size_t count)
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
	(void)rendered;
	(void)len;
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
		element_hashtable_create();
		init_peer(&owner_peer, false, &loop);
		owner_peer.send_message = send_message;
		init_peer(&call_peer, false, &loop);
		call_peer.send_message = send_message;
	}
	~F()
	{
		free_peer_resources(&call_peer);
		free_peer_resources(&owner_peer);
		element_hashtable_delete();
	}

	struct peer owner_peer;
	struct peer call_peer;
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

static void check_invalid_params(const cJSON *response)
{
	const cJSON *error = cJSON_GetObjectItem(response, "error");

	cJSON *code = cJSON_GetObjectItem(error, "code");
	if (code != NULL) {
		BOOST_CHECK_MESSAGE(code->type == cJSON_Number, "error code is not a number!");
		BOOST_CHECK_MESSAGE(code->valueint == INVALID_PARAMS_ERROR, "error code does not correspond to invalid params");
	} else {
		BOOST_FAIL("No code object!");
	}

	cJSON *message = cJSON_GetObjectItem(error, "message");
	if (message != NULL) {
		BOOST_CHECK_MESSAGE(message->type == cJSON_String, "message is not a string!");
		BOOST_CHECK_MESSAGE(strcmp(message->valuestring, "Invalid params") == 0, "message is not set to \"Invalid params\"!");
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

static bool response_is_error(const cJSON *response)
{
	const cJSON *error = cJSON_GetObjectItem(response, "error");
	return (error != NULL);
}

BOOST_FIXTURE_TEST_CASE(delete_nonexisting_method, F)
{
	const char path[] = "/foo/bar/";
	cJSON *request = create_add(path);

	cJSON *response = remove_element_from_peer(&owner_peer, request, path);
	BOOST_REQUIRE_MESSAGE(response != NULL, "remove_element_from_peer() had no response!");
	BOOST_CHECK_MESSAGE(response_is_error(response), "remove_element_from_peer() failed!");
	cJSON_Delete(request);
	cJSON_Delete(response);
}

BOOST_FIXTURE_TEST_CASE(call_wrong_path, F)
{
	const char path[] = "/foo/bar/";
	cJSON *request = create_add(path);
	cJSON *params = cJSON_GetObjectItem(request, "params");
	cJSON *json_path = cJSON_GetObjectItem(params, "path");

	cJSON *response = add_element_to_peer(&owner_peer, request, json_path->valuestring, NULL, NULL, 0x00, CONFIG_ROUTED_MESSAGES_TIMEOUT);
	BOOST_REQUIRE_MESSAGE(response != NULL, "add_element_to_peer() had no response!");
	BOOST_CHECK_MESSAGE(!response_is_error(response), "add_element_to_peer() failed!");
	cJSON_Delete(response);

	cJSON *call_json_rpc = create_call_json_rpc(method_no_args_path);
	response = set_or_call(&owner_peer, "/bar/foo", NULL, NULL, call_json_rpc, METHOD);
	cJSON_Delete(call_json_rpc);
	BOOST_REQUIRE_MESSAGE(response != NULL, "set_or_call() had no response!");
	check_invalid_params(response);
	cJSON_Delete(response);
	cJSON_Delete(request);
}

BOOST_FIXTURE_TEST_CASE(add_method_twice, F)
{
	const char path[] = "/foo/bar";
	cJSON *request = create_add(path);
	cJSON *params = cJSON_GetObjectItem(request, "params");
	cJSON *json_path = cJSON_GetObjectItem(params, "path");

	cJSON *response = add_element_to_peer(&owner_peer, request, json_path->valuestring, NULL, NULL, 0x00, CONFIG_ROUTED_MESSAGES_TIMEOUT);
	BOOST_REQUIRE_MESSAGE(response != NULL, "add_element_to_peer() had no response!");
	BOOST_CHECK_MESSAGE(!response_is_error(response), "add_element_to_peer() failed!");
	cJSON_Delete(response);

	response = add_element_to_peer(&owner_peer, request, json_path->valuestring, NULL, NULL, 0x00, CONFIG_ROUTED_MESSAGES_TIMEOUT);
	BOOST_REQUIRE_MESSAGE(response != NULL, "add_element_to_peer() had no response!");
	check_invalid_params(response);
	cJSON_Delete(response);
	cJSON_Delete(request);
}

BOOST_FIXTURE_TEST_CASE(add_method_existing_state, F)
{
	const char path[] = "/foo/bar";
	cJSON *request = create_add(path);
	cJSON *params = cJSON_GetObjectItem(request, "params");
	cJSON *json_path = cJSON_GetObjectItem(params, "path");
	cJSON *value = cJSON_GetObjectItem(params, "value");

	cJSON *response = add_element_to_peer(&owner_peer, request, json_path->valuestring, value, NULL, 0x00, CONFIG_ROUTED_MESSAGES_TIMEOUT);
	BOOST_REQUIRE_MESSAGE(response != NULL, "add_element_to_peer() had no response!");
	BOOST_CHECK_MESSAGE(!response_is_error(response), "add_element_to_peer() failed!");
	cJSON_Delete(response);

	response = add_element_to_peer(&owner_peer, request, json_path->valuestring, NULL, NULL, 0x00, CONFIG_ROUTED_MESSAGES_TIMEOUT);
	BOOST_REQUIRE_MESSAGE(response != NULL, "add_element_to_peer() had no response!");
	check_invalid_params(response);
	cJSON_Delete(response);
	cJSON_Delete(request);
}

BOOST_FIXTURE_TEST_CASE(call_on_state, F)
{
	const char path[] = "/foo/bar";
	cJSON *request = create_add(path);
	cJSON *params = cJSON_GetObjectItem(request, "params");
	cJSON *json_path = cJSON_GetObjectItem(params, "path");
	cJSON *value = cJSON_GetObjectItem(params, "value");

	cJSON *response = add_element_to_peer(&owner_peer, request, json_path->valuestring, value, NULL, 0x00, CONFIG_ROUTED_MESSAGES_TIMEOUT);
	BOOST_REQUIRE_MESSAGE(response != NULL, "add_element_to_peer() had no response!");
	BOOST_CHECK_MESSAGE(!response_is_error(response), "add_element_to_peer() failed!");
	cJSON_Delete(request);
	cJSON_Delete(response);

	cJSON *call_json_rpc = create_call_json_rpc(method_no_args_path);
	response = set_or_call(&call_peer, path, NULL, NULL, call_json_rpc, METHOD);
	cJSON_Delete(call_json_rpc);

	BOOST_REQUIRE_MESSAGE(response != NULL, "set_or_call) had no response!");
	check_invalid_params(response);
	cJSON_Delete(response);
}

BOOST_FIXTURE_TEST_CASE(double_free_method, F)
{
	const char path[] = "/foo/bar";
	cJSON *request = create_add(path);
	cJSON *params = cJSON_GetObjectItem(request, "params");
	cJSON *json_path = cJSON_GetObjectItem(params, "path");

	cJSON *response = add_element_to_peer(&owner_peer, request, json_path->valuestring, NULL, NULL, 0x00, CONFIG_ROUTED_MESSAGES_TIMEOUT);
	BOOST_REQUIRE_MESSAGE(response != NULL, "add_element_to_peer() had no response!");
	BOOST_CHECK_MESSAGE(!response_is_error(response), "add_element_to_peer() failed!");
	cJSON_Delete(response);

	response = remove_element_from_peer(&owner_peer, request, path);
	BOOST_REQUIRE_MESSAGE(response != NULL, "remove_element_from_peer() had no response!");
	BOOST_CHECK_MESSAGE(!response_is_error(response), "remove_element_from_peer() failed!");
	cJSON_Delete(response);

	response = remove_element_from_peer(&owner_peer, request, path);
	BOOST_REQUIRE_MESSAGE(response != NULL, "remove_element_from_peer() had no response!");
	BOOST_CHECK_MESSAGE(response_is_error(response), "remove_element_from_peer() did not fail!");
	cJSON_Delete(response);

	cJSON_Delete(request);
}

BOOST_FIXTURE_TEST_CASE(correct_call, F)
{
	const char path[] = "/foo/bar";
	cJSON *request = create_add(path);
	cJSON *params = cJSON_GetObjectItem(request, "params");
	cJSON *json_path = cJSON_GetObjectItem(params, "path");

	cJSON *response = add_element_to_peer(&owner_peer, request, json_path->valuestring, NULL, NULL, 0x00, CONFIG_ROUTED_MESSAGES_TIMEOUT);
	BOOST_REQUIRE_MESSAGE(response != NULL, "add_element_to_peer() had no response!");
	BOOST_CHECK_MESSAGE(!response_is_error(response), "add_element_to_peer() failed!");
	cJSON_Delete(response);

	cJSON *call_json_rpc = create_call_json_rpc(path);
	response = set_or_call(&call_peer, path, NULL, NULL, call_json_rpc, METHOD);
	cJSON_Delete(call_json_rpc);
	BOOST_CHECK_MESSAGE(response == (cJSON *)ROUTED_MESSAGE, "call() did not return ROUTED_MESSAGE!");
	cJSON_Delete(request);
}

BOOST_FIXTURE_TEST_CASE(set_wrong_id_type, F)
{
	const char path[] = "/foo/bar";
	cJSON *request = create_add(path);
	cJSON *params = cJSON_GetObjectItem(request, "params");
	cJSON *json_path = cJSON_GetObjectItem(params, "path");

	cJSON *response = add_element_to_peer(&owner_peer, request, json_path->valuestring, NULL, NULL, 0x00, CONFIG_ROUTED_MESSAGES_TIMEOUT);
	BOOST_REQUIRE_MESSAGE(response != NULL, "add_element_to_peer() had no response!");
	BOOST_CHECK_MESSAGE(!response_is_error(response), "add_element_to_peer() failed!");
	cJSON_Delete(response);

	cJSON *call_json_rpc = create_call_json_rpc_wrong_id_type(path);
	response = set_or_call(&call_peer, path, NULL, NULL, call_json_rpc, METHOD);
	cJSON_Delete(call_json_rpc);

	BOOST_REQUIRE_MESSAGE(response == NULL, "set_or_call() had a response despite illegal request id!");
	cJSON_Delete(request);
}
