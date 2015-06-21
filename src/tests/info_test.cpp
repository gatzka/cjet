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
#define BOOST_TEST_MODULE info

#include <arpa/inet.h>
#include <boost/test/unit_test.hpp>

#include "info.h"
#include "peer.h"

static char readback_buffer[10000];

extern "C" {
	void log_peer_err(const struct peer *p, const char *fmt, ...)
	{
	}

	int send_message(struct peer *p, const char *rendered, size_t len)
	{
		char *ptr = readback_buffer;
		uint32_t message_length = htonl(len);
		memcpy(ptr, &message_length, sizeof(message_length));
		ptr += 4;
		memcpy(ptr, rendered, len);
		return 0;
	}
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

BOOST_AUTO_TEST_CASE(create_info)
{
	cJSON *json_rpc = create_correct_info_method();
	int ret = handle_info(json_rpc, NULL);
	cJSON_Delete(json_rpc);
	BOOST_CHECK(ret == 0);

	char *ptr = readback_buffer;
	ptr += 4;
	cJSON *root = cJSON_Parse(ptr);
	BOOST_REQUIRE(root != NULL);

	cJSON *result = cJSON_GetObjectItem(root, "result");
	BOOST_REQUIRE(result != NULL);
	BOOST_CHECK(result->type == cJSON_Object);

	cJSON *name = cJSON_GetObjectItem(result, "name");
	BOOST_REQUIRE(name != NULL);
	BOOST_CHECK(name->type == cJSON_String);

	cJSON *version = cJSON_GetObjectItem(result, "version");
	BOOST_REQUIRE(version != NULL);
	BOOST_CHECK(version->type == cJSON_String);

	cJSON *protocol_version = cJSON_GetObjectItem(result, "protocolVersion");
	BOOST_REQUIRE(protocol_version != NULL);
	BOOST_CHECK(protocol_version->type == cJSON_String);

	cJSON *features = cJSON_GetObjectItem(result, "features");
	BOOST_REQUIRE(features != NULL);
	BOOST_REQUIRE(features->type == cJSON_Object);

	cJSON *batches = cJSON_GetObjectItem(features, "batches");
	BOOST_REQUIRE(batches != NULL);
	BOOST_CHECK((batches->type == cJSON_False) || (batches->type == cJSON_True));

	cJSON *authentication = cJSON_GetObjectItem(features, "authentication");
	BOOST_REQUIRE(authentication != NULL);
	BOOST_CHECK((authentication->type == cJSON_False) || (authentication->type == cJSON_True));

	cJSON *fetch = cJSON_GetObjectItem(features, "fetch");
	BOOST_REQUIRE(fetch != NULL);
	BOOST_CHECK(fetch->type == cJSON_String);
	BOOST_CHECK((::strcmp(fetch->valuestring, "full") == 0) || (::strcmp(fetch->valuestring, "simple")));

	cJSON_Delete(root);
}

