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
	int send_message(const struct peer *p, char *rendered, size_t len)
	{
		(void)p;
		char *ptr = readback_buffer;
		uint32_t message_length = htonl(len);
		memcpy(ptr, &message_length, sizeof(message_length));
		ptr += 4;
		memcpy(ptr, rendered, len);
		return 0;
	}

	struct peer *alloc_peer()
	{
		struct peer *p = (struct peer *)::malloc(sizeof(*p));
		init_peer(p, false, NULL);
		return p;
	}

	void free_peer(struct peer *p)
	{
		free_peer_resources(p);
		::free(p);
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

BOOST_AUTO_TEST_CASE(test_info_without_id)
{
	cJSON *root = cJSON_CreateObject();
	BOOST_REQUIRE(root != NULL);
	cJSON_AddStringToObject(root, "method", "info");

	cJSON *params = cJSON_CreateObject();
	BOOST_REQUIRE(params != NULL);
	cJSON_AddItemToObject(root, "params", params);

	struct peer *p = alloc_peer();
	int ret = handle_info(root, p);
	cJSON_Delete(root);
	BOOST_CHECK(ret == -1);

	free_peer(p);
}

BOOST_AUTO_TEST_CASE(create_info)
{
	struct peer *p = alloc_peer();
	p->send_message = send_message;
	cJSON *json_rpc = create_correct_info_method();
	int ret = handle_info(json_rpc, p);
	cJSON_Delete(json_rpc);
	BOOST_CHECK(ret == 0);

	char *ptr = readback_buffer;
	ptr += 4;
	cJSON *root = cJSON_Parse(ptr);
	if (root == NULL) {
		BOOST_FAIL("No root object");
		return;
	}

	cJSON *result = cJSON_GetObjectItem(root, "result");
	if (result == NULL) {
		BOOST_FAIL("No result object");
		return;
	}
	BOOST_CHECK(result->type == cJSON_Object);

	cJSON *name = cJSON_GetObjectItem(result, "name");
	if (name == NULL) {
		BOOST_FAIL("No name object");
		return;
	}
	BOOST_CHECK(name->type == cJSON_String);

	cJSON *version = cJSON_GetObjectItem(result, "version");
	if (name == NULL) {
		BOOST_FAIL("No version object");
		return;
	}
	BOOST_CHECK(version->type == cJSON_String);

	cJSON *protocol_version = cJSON_GetObjectItem(result, "protocolVersion");
	if (protocol_version == NULL) {
		BOOST_FAIL("No protocolVersion object");
		return;
	}
	BOOST_CHECK(protocol_version->type == cJSON_String);

	cJSON *features = cJSON_GetObjectItem(result, "features");
	if (features == NULL) {
		BOOST_FAIL("No features object");
		return;
	}
	BOOST_REQUIRE(features->type == cJSON_Object);

	cJSON *batches = cJSON_GetObjectItem(features, "batches");
	if (batches == NULL) {
		BOOST_FAIL("No batches object");
		return;
	}
	BOOST_CHECK((batches->type == cJSON_False) || (batches->type == cJSON_True));

	cJSON *authentication = cJSON_GetObjectItem(features, "authentication");
	if (authentication == NULL) {
		BOOST_FAIL("No authentication object");
		return;
	}
	BOOST_CHECK((authentication->type == cJSON_False) || (authentication->type == cJSON_True));

	cJSON *fetch = cJSON_GetObjectItem(features, "fetch");
	if (fetch == NULL) {
		BOOST_FAIL("No fetch object");
		return;
	}
	BOOST_CHECK(fetch->type == cJSON_String);
	BOOST_CHECK((::strcmp(fetch->valuestring, "full") == 0) || (::strcmp(fetch->valuestring, "simple")));

	cJSON_Delete(root);

	free_peer(p);
}

