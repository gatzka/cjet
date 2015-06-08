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

#include "config.h"
#include "json/cJSON.h"
#include "peer.h"
#include "router.h"
#include "state.h"

extern "C" {

	int create_state_hashtable(void)
	{
		return 0;
	}

	void delete_state_hashtable(void)
	{
	}

	void remove_routing_info_from_peer(const struct peer *p)
	{
	}

	void remove_all_states_from_peer(struct peer *p)
	{
	}

	void delete_routing_table(struct peer *p)
	{
	}

	int add_routing_table(struct peer *p)
	{
		return 0;
	}

	void remove_peer_from_routing_table(const struct peer *p, const struct peer *peer_to_remove)
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


struct F {
	F()
	{
		create_state_hashtable();
		p = alloc_peer(-1);
	}
	~F()
	{
		free_peer(p);
		delete_state_hashtable();
	}

	struct peer *p;
};

static cJSON *create_config_request_with_name(const char *name)
{
	cJSON *params = cJSON_CreateObject();
	cJSON_AddFalseToObject(params, "debug");
	cJSON_AddStringToObject(params, "name", name);
	return params;
}

static cJSON *create_config_request_with_no_name(void)
{
	cJSON *params = cJSON_CreateObject();
	cJSON_AddFalseToObject(params, "debug");
	return params;
}

static cJSON *create_config_request_with_name_of_wrong_type(void)
{
	cJSON *params = cJSON_CreateObject();
	cJSON_AddFalseToObject(params, "debug");
	cJSON_AddFalseToObject(params, "name");
	return params;
}

BOOST_FIXTURE_TEST_CASE(config_name, F)
{
	const char *peer_name = "test_peer";
	cJSON *params = create_config_request_with_name(peer_name);
	cJSON *error = config_peer(p, params);
	BOOST_CHECK(error == NULL);
	BOOST_CHECK(::strcmp(peer_name, p->name) == 0);
	cJSON_Delete(params);
}

BOOST_FIXTURE_TEST_CASE(config_no_name, F)
{
	const char *peer_name = NULL;
	cJSON *params = create_config_request_with_no_name();
	cJSON *error = config_peer(p, params);
	BOOST_CHECK(error == NULL);
	BOOST_CHECK(peer_name == NULL);
	cJSON_Delete(params);
}

BOOST_FIXTURE_TEST_CASE(config_wrong_type_of_name, F)
{
	const char *peer_name = NULL;
	cJSON *params = create_config_request_with_name_of_wrong_type();
	cJSON *error = config_peer(p, params);
	BOOST_CHECK(error != NULL);
	BOOST_CHECK(peer_name == NULL);
	cJSON_Delete(error);
	cJSON_Delete(params);
}

BOOST_FIXTURE_TEST_CASE(config_name_twice, F)
{
	const char *peer_name1 = "test_peer";
	cJSON *params = create_config_request_with_name(peer_name1);
	cJSON *error = config_peer(p, params);
	BOOST_CHECK(error == NULL);
	BOOST_CHECK(::strcmp(peer_name1, p->name) == 0);
	cJSON_Delete(params);

	const char *peer_name2 = "peer_test";
	params = create_config_request_with_name(peer_name2);
	error = config_peer(p, params);
	BOOST_CHECK(error == NULL);
	BOOST_CHECK(::strcmp(peer_name2, p->name) == 0);
	cJSON_Delete(params);
}

