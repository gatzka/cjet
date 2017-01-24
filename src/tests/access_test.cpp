/*
 * The MIT License (MIT)
 *
 * Copyright (c) <2016> <Stephan Gatzka>
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
#define BOOST_TEST_MODULE state/method access tests

#include <boost/test/unit_test.hpp>
#include <list>

#include <stdio.h>

#include "authenticate.h"
#include "eventloop.h"
#include "fetch.h"
#include "json/cJSON.h"
#include "parse.h"
#include "element.h"
#include "table.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

enum event {
	UNKNOWN_EVENT,
	ADD_EVENT,
	CHANGE_EVENT,
	REMOVE_EVENT
};

static struct io_event *timer_ev;
static struct eventloop loop;

static const char users[] = "users";
static const char admins[] = "admin";

static cJSON *user_auth;

static struct peer fetch_peer;

static std::list<cJSON*> fetch_events;

extern "C" {
	const cJSON *credentials_ok(const char *user_name, char *passwd)
	{
		(void)passwd;

		if (std::strcmp(user_name, "user") == 0) {
			return user_auth;
		}

		return NULL;
	}

	cJSON *change_password(const struct peer *p, const cJSON *request, const char *user, char *passwd)
	{
		(void)p;
		(void)request;
		(void)user;
		(void)passwd;
		return NULL;
	}

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

static cJSON *parse_send_buffer(const char *json)
{
	const char *end_parse;
	cJSON *root = cJSON_ParseWithOpts(json, &end_parse, 0);
	return root;
}

static int send_message(const struct peer *p, char *rendered, size_t len)
{
	(void)len;
	if (p == &fetch_peer) {
		cJSON *fetch_event = parse_send_buffer(rendered);
		fetch_events.push_back(fetch_event);
	}

	return 0;
}

static enum eventloop_return fake_add(const void *this_ptr, const struct io_event *ev)
{
	(void)this_ptr;
	timer_ev = (struct io_event *)ev;
	return EL_CONTINUE_LOOP;
}

static void fake_remove(const void *this_ptr, const struct io_event *ev)
{
	(void)this_ptr;
	(void)ev;
	timer_ev = NULL;
	return;
}

static cJSON *create_fetch(const char *path_equals_string)
{
	cJSON *params = cJSON_CreateObject();
	BOOST_REQUIRE(params != NULL);
	cJSON_AddStringToObject(params, "id", "fetch_id_1");
	cJSON *fetch_path = cJSON_CreateObject();
	BOOST_REQUIRE(fetch_path != NULL);
	cJSON_AddItemToObject(params, "path", fetch_path);
	if (strlen(path_equals_string)) {
		cJSON_AddStringToObject(fetch_path, "equals", path_equals_string);
	}

	cJSON *root = cJSON_CreateObject();
	cJSON_AddItemToObject(root, "params", params);
	cJSON_AddStringToObject(root, "id", "fetch_request_1");
	cJSON_AddStringToObject(root, "method", "fetch");
	return root;
}

static enum event get_event_from_json(cJSON *json)
{
	cJSON *params = cJSON_GetObjectItem(json, "params");
	if (params == NULL) return UNKNOWN_EVENT;
	cJSON *event = cJSON_GetObjectItem(params, "event");
	if (event == NULL) return UNKNOWN_EVENT;
	if (event->type != cJSON_String) return UNKNOWN_EVENT;
	if (std::strcmp(event->valuestring, "add") == 0) return ADD_EVENT;
	if (std::strcmp(event->valuestring, "change") == 0) return CHANGE_EVENT;
	if (std::strcmp(event->valuestring, "remove") == 0) return REMOVE_EVENT;
	return UNKNOWN_EVENT;
}

static bool response_is_error(const cJSON *response)
{
	const cJSON *error = cJSON_GetObjectItem(response, "error");
	return (error != NULL);
}

static void perform_fetch(const char *fetch_path)
{
	struct fetch *f = NULL;
	cJSON *request = create_fetch(fetch_path);
	cJSON *response;
	int ret = add_fetch_to_peer(&fetch_peer, request, &f, &response);
	BOOST_REQUIRE_MESSAGE(ret == 0, "add_fetch_to_peer() failed!");
	response = add_fetch_to_states(&fetch_peer, request, f);
	BOOST_REQUIRE_MESSAGE(response != NULL, "add_fetch_to_states() had no response!");
	BOOST_CHECK_MESSAGE(!response_is_error(response), "add_fetch_to_states() failed!");
	cJSON_Delete(response);
	cJSON_Delete(request);
}

static cJSON *create_add_with_access(const char *path, cJSON *access)
{
	cJSON *params = cJSON_CreateObject();
	BOOST_REQUIRE(params != NULL);
	cJSON_AddStringToObject(params, "path", path);
	cJSON_AddItemToObject(params, "value", cJSON_CreateNumber(1234));
	cJSON_AddItemToObject(params, "access", access);

	cJSON *root = cJSON_CreateObject();
	cJSON_AddItemToObject(root, "params", params);
	cJSON_AddStringToObject(root, "id", "add_request_1");
	cJSON_AddStringToObject(root, "method", "add");
	return root;
}

static cJSON *create_authentication_with_params(cJSON *params){

	cJSON *root = cJSON_CreateObject();
	cJSON_AddItemToObject(root, "params", params);
	cJSON_AddStringToObject(root, "id", "auth_request");
	cJSON_AddStringToObject(root, "method", "authenticate");
	return root;
}

static cJSON *create_authentication()
{
	cJSON *params = cJSON_CreateObject();
	BOOST_REQUIRE(params != NULL);
	cJSON_AddStringToObject(params, "user", "user");
	cJSON_AddStringToObject(params, "password", "password");
	return create_authentication_with_params(params);
}

char *extract_error_message(const cJSON *request_error){

	const cJSON *error = cJSON_GetObjectItem(request_error, "error");
	BOOST_REQUIRE_MESSAGE(error != NULL, "No error object given!");

	const cJSON *error_data = cJSON_GetObjectItem(error, "data");
	BOOST_REQUIRE_MESSAGE(error_data != NULL, "No data object within given error message!");

	const cJSON *error_string_reason = cJSON_GetObjectItem(error_data, "reason");
	if(error_string_reason != NULL){
		BOOST_REQUIRE_MESSAGE(error_string_reason ->type == cJSON_String, "Given reason is no string!");
		return error_string_reason ->valuestring;
	} else {
		const cJSON *error_string_auth = cJSON_GetObjectItem(error_data, "fetched before authenticate");
		BOOST_REQUIRE_MESSAGE(error_string_auth != NULL, "No object reason given within error message!");
		return error_string_auth->string;
	}
}

struct F {
	F()
	{
		timer_ev = NULL;
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
		init_peer(&fetch_peer, false, &loop);
		fetch_peer.send_message = send_message;

		cJSON *groups = cJSON_CreateArray();
		cJSON_AddItemToArray(groups, cJSON_CreateString(admins));
		cJSON_AddItemToArray(groups, cJSON_CreateString(users));
		cJSON_AddItemToArray(groups, cJSON_CreateString("operators"));
		cJSON_AddItemToArray(groups, cJSON_CreateString("viewers"));
		create_groups();

		add_groups(groups);
		cJSON_Delete(groups);

		user_auth = cJSON_CreateObject();
		cJSON *fetch_groups = cJSON_CreateArray();
		cJSON_AddItemToArray(fetch_groups, cJSON_CreateString(users));
		cJSON_AddItemToObject(user_auth, "fetchGroups", fetch_groups);
		cJSON *set_groups = cJSON_CreateArray();
		cJSON_AddItemToArray(set_groups, cJSON_CreateString(users));
		cJSON_AddItemToObject(user_auth, "setGroups", set_groups);
		cJSON *call_groups = cJSON_CreateArray();
		cJSON_AddItemToArray(call_groups, cJSON_CreateString(users));
		cJSON_AddItemToObject(user_auth, "callGroups", call_groups);

		password = ::strdup("password");
	}

	~F()
	{
		::free(password);

		while (!fetch_events.empty()) {
			cJSON *ptr = fetch_events.front();
			fetch_events.pop_front();
			cJSON_Delete(ptr);
		}
		cJSON_Delete(user_auth);
		free_groups();
		free_peer_resources(&fetch_peer);
		free_peer_resources(&owner_peer);
		element_hashtable_delete();
	}

	char *password;
	struct peer owner_peer;
};
BOOST_FIXTURE_TEST_CASE(authenticate_without_param, F)
{
	cJSON *auth = create_authentication_with_params(NULL);

	cJSON *response = handle_authentication(&fetch_peer, auth);
	BOOST_REQUIRE_MESSAGE(response != NULL, "Fetch peer authentication had no response!");
	BOOST_CHECK_MESSAGE(response_is_error(response), "No error returned and successfully authenticated, even without giving any parameters.");
	char *error_message = extract_error_message(response);
	BOOST_CHECK_MESSAGE(!std::strcmp(error_message, "no params found"), "The expected error is: \"no params found\", but was: \"" <<error_message<<"\".");

	cJSON_Delete(response);
	response = handle_change_password(&fetch_peer, auth);
	error_message = extract_error_message(response);
	BOOST_CHECK_MESSAGE(!std::strcmp(error_message, "no params found"), "The expected error is: \"no params found\", but was: \"" <<error_message<<"\".");

	cJSON_Delete(auth);
	cJSON_Delete(response);
}

BOOST_FIXTURE_TEST_CASE(authenticate_without_param_user, F)
{
	cJSON *params = cJSON_CreateObject();
	BOOST_REQUIRE(params != NULL);
	cJSON_AddStringToObject(params, "password", "password");

	cJSON *auth = create_authentication_with_params(params);

	cJSON *response = handle_authentication(&fetch_peer, auth);
	BOOST_REQUIRE_MESSAGE(response != NULL, "fetch peer authentication had no response!");
	BOOST_CHECK_MESSAGE(response_is_error(response), "No error returned and successfully authenticated, even without providing a username.");
	char *error_message = extract_error_message(response);
	BOOST_CHECK_MESSAGE(!std::strcmp(error_message, "no user given"), "The expected error is: \"no user given\", but was: \"" <<error_message<<"\".");

	cJSON_Delete(response);
	response = handle_change_password(&fetch_peer, auth);
	error_message = extract_error_message(response);
	BOOST_CHECK_MESSAGE(!std::strcmp(error_message, "no user given"), "The expected error is: \"no user given\", but was: \"" <<error_message<<"\".");

	cJSON_Delete(auth);
	cJSON_Delete(response);
}

BOOST_FIXTURE_TEST_CASE(authenticate_with_param_int_user, F)
{
	cJSON *params = cJSON_CreateObject();
	BOOST_REQUIRE(params != NULL);
	cJSON_AddNumberToObject(params, "user", 42);
	cJSON_AddStringToObject(params, "password", "password");

	cJSON *auth = create_authentication_with_params(params);

	cJSON *response = handle_authentication(&fetch_peer, auth);
	BOOST_REQUIRE_MESSAGE(response != NULL, "fetch peer authentication had no response!");
	BOOST_CHECK_MESSAGE(response_is_error(response), "No error returned and successfully authenticated, even with int as username");
	char *error_message = extract_error_message(response);
	BOOST_CHECK_MESSAGE(!std::strcmp(error_message,"user is not a string"), "The expected error is: \"user is not a string\", but was: \"" <<error_message<<"\".");

	cJSON_Delete(response);
	response = handle_change_password(&fetch_peer, auth);
	error_message = extract_error_message(response);
	BOOST_CHECK_MESSAGE(!std::strcmp(error_message,"user is not a string"), "The expected error is: \"user is not a string\", but was: \"" <<error_message<<"\".");

	cJSON_Delete(auth);
	cJSON_Delete(response);
}

BOOST_FIXTURE_TEST_CASE(authenticate_without_param_password, F)
{
	cJSON *params = cJSON_CreateObject();
	BOOST_REQUIRE(params != NULL);
	cJSON_AddStringToObject(params, "user", "user");

	cJSON *auth = create_authentication_with_params(params);

	cJSON *response = handle_authentication(&fetch_peer, auth);
	BOOST_REQUIRE_MESSAGE(response != NULL, "fetch peer authentication had no response!");
	BOOST_CHECK_MESSAGE(response_is_error(response), "No error returned and successfully authenticated, even without providing a password.");
	char *error_message = extract_error_message(response);
	BOOST_CHECK_MESSAGE(!std::strcmp(error_message, "no password given"), "The expected error is: \"no password given\", but was: \"" <<error_message<<"\".");

	cJSON_Delete(response);
	response = handle_change_password(&fetch_peer, auth);
	error_message = extract_error_message(response);
	BOOST_CHECK_MESSAGE(!std::strcmp(error_message, "no password given"), "The expected error is: \"no password given\", but was: \"" <<error_message<<"\".");

	cJSON_Delete(auth);
	cJSON_Delete(response);
}

BOOST_FIXTURE_TEST_CASE(authenticate_with_param_int_password, F)
{
	cJSON *params = cJSON_CreateObject();
	BOOST_REQUIRE(params != NULL);
	cJSON_AddStringToObject(params, "user", "user");
	cJSON_AddNumberToObject(params, "password", 42);

	cJSON *auth = create_authentication_with_params(params);

	cJSON *response = handle_authentication(&fetch_peer, auth);
	BOOST_REQUIRE_MESSAGE(response != NULL, "fetch peer authentication had no response!");
	BOOST_CHECK_MESSAGE(response_is_error(response), "No error returned and successfully authenticated, even with int as password");

	char *error_message = extract_error_message(response);
	BOOST_CHECK_MESSAGE(!std::strcmp(error_message, "password is not a string"), "The expected error is: \"password is not a string\", but was: \"" <<error_message<<"\".");

	cJSON_Delete(response);
	response = handle_change_password(&fetch_peer, auth);
	error_message = extract_error_message(response);
	BOOST_CHECK_MESSAGE(!std::strcmp(error_message,"password is not a string"), "The expected error is: \"password is not a string\", but was: \"" <<error_message<<"\".");

	cJSON_Delete(auth);
	cJSON_Delete(response);
}

BOOST_FIXTURE_TEST_CASE(authenticate_after_fetch, F){
	struct fetch *f = NULL;
	cJSON *request = create_fetch("foo/bar");
	cJSON *response;
	int ret = add_fetch_to_peer(&fetch_peer, request, &f, &response);
	BOOST_REQUIRE_MESSAGE(ret == 0, "add_fetch_to_peer() failed!");

	cJSON *auth = create_authentication();

	response = handle_authentication(&fetch_peer, auth );
	BOOST_REQUIRE_MESSAGE(response != NULL, "fetch peer authentication had no response!");

	BOOST_CHECK_MESSAGE(response_is_error(response), "No error returned and successfully authenticated, even after peer added fetches.");
	char *error_message = extract_error_message(response);
	BOOST_CHECK_MESSAGE(!std::strcmp(error_message, "fetched before authenticate"), "The expected error is: \"fetched before authenticate\", but was: \"" <<error_message<<"\".");

	cJSON_Delete(request);
	cJSON_Delete(auth);
	cJSON_Delete(response);
}

BOOST_FIXTURE_TEST_CASE(fetch_state_allowed, F)
{
	const char path[] = "/foo/bar/";

	cJSON *access = cJSON_CreateObject();
	cJSON *fetch_groups = cJSON_CreateArray();
	cJSON_AddItemToArray(fetch_groups, cJSON_CreateString(users));
	cJSON_AddItemToObject(access, "fetchGroups", fetch_groups);

	cJSON *request = create_add_with_access(path, access);

	cJSON *response = add_element_to_peer(&owner_peer, request);
	BOOST_REQUIRE_MESSAGE(response != NULL, "add_element_to_peer() had no response!");
	BOOST_CHECK_MESSAGE(!response_is_error(response), "add_element_to_peer() failed!");
	cJSON_Delete(request);
	cJSON_Delete(response);

	request = create_authentication();
	response = handle_authentication(&fetch_peer, request);
	BOOST_REQUIRE_MESSAGE(response != NULL, "fetch peer authentication had no response!");
	BOOST_CHECK_MESSAGE(!response_is_error(response), "fetch peer authentication failed!");
	cJSON_Delete(request);
	cJSON_Delete(response);

	perform_fetch(path);
	BOOST_REQUIRE_MESSAGE(fetch_events.size() == 1, "Number of emitted events != 1!");
	cJSON *json = fetch_events.front();
	fetch_events.pop_front();
	event event = get_event_from_json(json);
	BOOST_CHECK_MESSAGE(event == ADD_EVENT, "Emitted event is not an ADD event!");
	cJSON_Delete(json);
	remove_all_fetchers_from_peer(&fetch_peer);
}

BOOST_FIXTURE_TEST_CASE(fetch_state_not_allowed, F)
{
	const char path[] = "/foo/bar/";

	cJSON *access = cJSON_CreateObject();
	cJSON *fetch_groups = cJSON_CreateArray();
	cJSON_AddItemToArray(fetch_groups, cJSON_CreateString(admins));
	cJSON_AddItemToObject(access, "fetchGroups", fetch_groups);

	cJSON *request = create_add_with_access(path, access);

	cJSON *response = add_element_to_peer(&owner_peer, request);
	BOOST_REQUIRE_MESSAGE(response != NULL, "add_element_to_peer() had no response!");
	BOOST_CHECK_MESSAGE(!response_is_error(response), "add_element_to_peer() failed!");
	cJSON_Delete(request);
	cJSON_Delete(response);

	request = create_authentication();
	response = handle_authentication(&fetch_peer, request);
	BOOST_REQUIRE_MESSAGE(response != NULL, "fetch peer authentication had no response!");
	BOOST_CHECK_MESSAGE(!response_is_error(response), "fetch peer authentication failed!");
	cJSON_Delete(request);
	cJSON_Delete(response);

	perform_fetch(path);
	BOOST_REQUIRE_MESSAGE(fetch_events.size() == 0, "Number of emitted events != 0!");
	remove_all_fetchers_from_peer(&fetch_peer);
}


BOOST_AUTO_TEST_CASE(add_group_twice)
{
	cJSON *groups = cJSON_CreateArray();
	cJSON_AddItemToArray(groups, cJSON_CreateString("viewers"));
	cJSON_AddItemToArray(groups, cJSON_CreateString("viewers"));
	create_groups();
	int ret = add_groups(groups);
	cJSON_Delete(groups);
	BOOST_CHECK_MESSAGE(ret == 0, "adding a group twice failed!");
	free_groups();
}

BOOST_AUTO_TEST_CASE(add_too_many_groups)
{
	create_groups();

	cJSON *groups = cJSON_CreateArray();
	for (unsigned int i = 0; i <= sizeof(group_t) * 8; i++) {
		char buffer[10];
		::sprintf(buffer, "%s%d", "viewer", i);
		cJSON_AddItemToArray(groups, cJSON_CreateString(buffer));
	}

	int ret = add_groups(groups);
	cJSON_Delete(groups);
	BOOST_CHECK_MESSAGE(ret == -1, "adding lots of groups did not fail!");
	free_groups();
}

BOOST_AUTO_TEST_CASE(add_non_array_group)
{
	create_groups();

	cJSON *groups = cJSON_CreateFalse();
	int ret = add_groups(groups);
	cJSON_Delete(groups);
	BOOST_CHECK_MESSAGE(ret == -1, "adding a non-array group did not fail!");
	free_groups();
}

BOOST_AUTO_TEST_CASE(add_no_string_in_group)
{
	create_groups();

	cJSON *groups = cJSON_CreateArray();
	cJSON_AddItemToArray(groups, cJSON_CreateFalse());
	int ret = add_groups(groups);
	cJSON_Delete(groups);
	BOOST_CHECK_MESSAGE(ret == -1, "adding a non string group member did not fail!");
	free_groups();
}
