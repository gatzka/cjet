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

#include "config.h"
#include "json/cJSON.h"
#include "peer.h"
#include "router.h"
#include "state.h"

extern "C" {
	int send_message(struct peer *p, const char *rendered, size_t len)
	{
		return 0;
	}

	void remove_all_states_from_peer(struct peer *p)
	{
	}

	int add_io(struct peer *p)
	{
		return 0;
	}

	void remove_io(const struct peer *p)
	{
		return;
	}

	void remove_all_methods_from_peer(struct peer *p)
	{
	}

	void remove_all_fetchers_from_peer(struct peer *p)
	{
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
		p = alloc_peer(-1);
	}
	~F()
	{
		free_peer(p);
	}

	struct peer *p;
};

BOOST_FIXTURE_TEST_CASE(handle_response, F)
{
	cJSON *response = create_response_no_id();
	cJSON *result = cJSON_GetObjectItem(response, "result");
	int ret = handle_routing_response(response, result, "result", p);
	BOOST_CHECK(ret == -1);

	response = create_response_wrong_id();
	result = cJSON_GetObjectItem(response, "result");
	ret = handle_routing_response(response, result, "result", p);
	BOOST_CHECK(ret == -1);
}

