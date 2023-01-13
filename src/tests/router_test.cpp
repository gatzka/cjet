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
#define BOOST_TEST_MODULE router

#include <boost/test/unit_test.hpp>

#include "alloc.h"
#include "compiler.h"
#include "json/cJSON.h"
#include "peer.h"
#include "router.h"

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

static cJSON *create_response_no_id()
{
	cJSON *root = cJSON_CreateObject();
	BOOST_REQUIRE(root != NULL);
	cJSON_AddStringToObject(root, "result", "o.k.");

	cJSON *params = cJSON_CreateObject();
	BOOST_REQUIRE(params != NULL);
	cJSON_AddItemToObject(root, "params", params);
	return root;
}

static cJSON *create_response_wrong_id()
{
	cJSON *root = cJSON_CreateObject();
	BOOST_REQUIRE(root != NULL);
	cJSON_AddTrueToObject(root, "id");
	cJSON_AddStringToObject(root, "result", "o.k.");

	cJSON *params = cJSON_CreateObject();
	BOOST_REQUIRE(params != NULL);
	cJSON_AddItemToObject(root, "params", params);
	return root;
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


BOOST_FIXTURE_TEST_CASE(uuid_test, F)
{
	peer requestingPeer;
	peer owningPeer;
	cJSON *request = cJSON_CreateObject();
	cJSON_AddStringToObject(request, "id", "the id");
	const cJSON *request_id = cJSON_GetObjectItem(request, "id");
	// allocation has to create a unique routed request id! Two peers might send a request with the same id!
	struct routing_request *routing_request1 = alloc_routing_request(&requestingPeer, &owningPeer, request_id);
	struct routing_request *routing_request2 = alloc_routing_request(&requestingPeer, &owningPeer, request_id);

	std::string id1 = routing_request1->id;
	std::string id2 = routing_request2->id;

	BOOST_REQUIRE(id1 != id2);
	cjet_free(routing_request1);
	cjet_free(routing_request2);
	cJSON_Delete(request);
}


BOOST_FIXTURE_TEST_CASE(handle_response, F)
{
	cJSON *response = create_response_no_id();
	cJSON *result = cJSON_GetObjectItem(response, "result");
	int ret = handle_routing_response(response, result, "result", &p);
	BOOST_CHECK(ret == -1);
	cJSON_Delete(response);

	response = create_response_wrong_id();
	result = cJSON_GetObjectItem(response, "result");
	ret = handle_routing_response(response, result, "result", &p);
	BOOST_CHECK(ret == -1);
	cJSON_Delete(response);
}
