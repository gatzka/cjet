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
static bool message_for_wrong_peer;

static enum event fetch_peer_1_event;
static enum event fetch_peer_2_event;

static cJSON *parse_send_buffer(void)
{
	char *read_ptr = send_buffer;
	const char *end_parse;
	cJSON *root = cJSON_ParseWithOpts(read_ptr, &end_parse, 0);
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

	void remove_all_methods_from_peer(struct peer *p)
	{
	}
}

struct F {
	F()
	{
		create_state_hashtable();
		p = alloc_peer(-1);
		fetch_peer_1 = alloc_peer(-1);
		fetch_peer_2 = alloc_peer(-1);
		message_for_wrong_peer = false;
	}
	~F()
	{
		free_peer(fetch_peer_1);
		free_peer(fetch_peer_2);
		free_peer(p);
		delete_state_hashtable();
	}

	struct peer *p;
};

//static cJSON *create_fetch_params(const char *path_string)
//{
//	cJSON *root = cJSON_CreateObject();
//	BOOST_REQUIRE(root != NULL);
//	cJSON_AddStringToObject(root, "id", "fetch_id_1");
//	cJSON *path = cJSON_CreateObject();
//	BOOST_REQUIRE(path != NULL);
//	cJSON_AddItemToObject(root, "path", path);
//	cJSON_AddStringToObject(path, "equals", path_string);

//	return root;
//}

static cJSON *create_fetch_params_igoring_case(const char *path_string)
{
	cJSON *root = cJSON_CreateObject();
	BOOST_REQUIRE(root != NULL);
	cJSON_AddStringToObject(root, "id", "fetch_id_1");
	cJSON *path = cJSON_CreateObject();
	BOOST_REQUIRE(path != NULL);
	cJSON_AddItemToObject(root, "path", path);
	cJSON_AddStringToObject(path, "equals", path_string);
	cJSON_AddBoolToObject(root, "caseInsensitive", 1);

	return root;
}


BOOST_FIXTURE_TEST_CASE(two_fetch_and_change_ignoring_case, F)
{
	const char *path = "/foo/bar/";
	const char *path_upper = "/FOO/BAR/";
	int state_value = 12345;
	cJSON *value = cJSON_CreateNumber(state_value);

	cJSON *error = add_state_to_peer(p, path, value);
	BOOST_CHECK(error == NULL);

	cJSON_Delete(value);

	struct state *s = get_state(path);
	BOOST_CHECK(s->value->valueint == state_value);

	struct fetch *f = NULL;
	cJSON *params = create_fetch_params_igoring_case(path_upper);
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

