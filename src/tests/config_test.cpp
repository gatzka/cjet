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
#define BOOST_TEST_MODULE config

#include <boost/test/unit_test.hpp>

#include "config.h"
#include "json/cJSON.h"
#include "peer.h"

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

struct F {
	F()
	{
		init_peer(&p, false, NULL);
	}

	~F()
	{
		free_peer_resources(&p);
	}

	struct peer p;
};

static cJSON *create_root()
{
	cJSON *params = cJSON_CreateObject();
	cJSON_AddFalseToObject(params, "debug");

	cJSON *root = cJSON_CreateObject();
	cJSON_AddItemToObject(root, "params", params);
	cJSON_AddStringToObject(root, "id", "config_request_1");
	cJSON_AddStringToObject(root, "method", "config");
	return root;
}

static cJSON *create_config_request_with_name(const char *name)
{
	cJSON *root = create_root();
	cJSON *params = cJSON_GetObjectItem(root, "params");
	cJSON_AddStringToObject(params, "name", name);

	return root;
}

static cJSON *create_config_request_with_no_name(void)
{
	return create_root();
}

static cJSON *create_config_request_with_name_of_wrong_type(void)
{
	cJSON *root = create_root();
	cJSON *params = cJSON_GetObjectItem(root, "params");
	cJSON_AddFalseToObject(params, "name");
	return root;
}

static bool response_is_error(const cJSON *response)
{
	const cJSON *error = cJSON_GetObjectItem(response, "error");
	return (error != NULL);
}

BOOST_FIXTURE_TEST_CASE(config_name, F)
{
	const char *peer_name = "test_peer";
	cJSON *request = create_config_request_with_name(peer_name);
	cJSON *params = cJSON_GetObjectItem(request, "params");
	cJSON *response = config_peer(&p, request, params);
	BOOST_REQUIRE_MESSAGE(response != NULL, "No response for config request!");
	BOOST_CHECK_MESSAGE(!response_is_error(response), "config_peer() failed!");
	BOOST_CHECK_MESSAGE(::strcmp(peer_name, p.name) == 0, "Peer name was not set!");
	cJSON_Delete(request);
	cJSON_Delete(response);
}

BOOST_FIXTURE_TEST_CASE(config_no_name, F)
{
	const char *peer_name = NULL;
	cJSON *request = create_config_request_with_no_name();
	cJSON *params = cJSON_GetObjectItem(request, "params");
	cJSON *response = config_peer(&p, request, params);
	BOOST_REQUIRE_MESSAGE(response != NULL, "No response for config request!");
	BOOST_CHECK_MESSAGE(!response_is_error(response), "config_peer() failed!");
	BOOST_CHECK_MESSAGE(peer_name == NULL, "Peer name was set via no name request!");
	cJSON_Delete(request);
	cJSON_Delete(response);
}

BOOST_FIXTURE_TEST_CASE(config_wrong_type_of_name, F)
{
	const char *peer_name = NULL;
	cJSON *request = create_config_request_with_name_of_wrong_type();
	cJSON *params = cJSON_GetObjectItem(request, "params");
	cJSON *response = config_peer(&p, request, params);
	BOOST_REQUIRE_MESSAGE(response != NULL, "No response for config request!");
	BOOST_CHECK_MESSAGE(response_is_error(response), "config_peer() did not fail!");
	BOOST_CHECK_MESSAGE(peer_name == NULL, "Peer name was set via illegal request!");
	cJSON_Delete(request);
	cJSON_Delete(response);
}

BOOST_FIXTURE_TEST_CASE(config_name_twice, F)
{
	const char *peer_name1 = "test_peer";
	cJSON *request = create_config_request_with_name(peer_name1);
	cJSON *params = cJSON_GetObjectItem(request, "params");
	cJSON *response = config_peer(&p, request, params);
	BOOST_REQUIRE_MESSAGE(response != NULL, "No response for config request!");
	BOOST_CHECK_MESSAGE(!response_is_error(response), "config_peer() failed!");
	BOOST_CHECK_MESSAGE(::strcmp(peer_name1, p.name) == 0, "Peer name was not set!");
	cJSON_Delete(request);
	cJSON_Delete(response);

	const char *peer_name2 = "peer_test";
	request = create_config_request_with_name(peer_name2);
	params = cJSON_GetObjectItem(request, "params");
	response = config_peer(&p, request, params);
	BOOST_REQUIRE_MESSAGE(response != NULL, "No response for config request!");
	BOOST_CHECK_MESSAGE(!response_is_error(response), "config_peer() failed!");
	BOOST_CHECK_MESSAGE(::strcmp(peer_name2, p.name) == 0, "Peer name was not set!");
	cJSON_Delete(request);
	cJSON_Delete(response);
}
