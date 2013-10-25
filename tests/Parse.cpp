#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MAIN
#define BOOST_TEST_MODULE parse JSON

#include <arpa/inet.h>
#include <boost/test/unit_test.hpp>

#include "../cJSON.h"
#include "../parse.h"
#include "../state.h"

static const char correct_json[] = "{\"id\": 7384,\"method\": \"add\",\"params\":{\"path\": \"foo/bar/state\",\"value\": 123}}";
static const char wrong_json[] = "{\"id\": 7384,\"method\": add\",\"params\":{\"path\": \"foo/bar/state\",\"value\": 123}}";
static const char json_no_method[] = "{\"id\": 7384,\"meth\": \"add\",\"params\":{\"path\": \"foo/bar/state\",\"value\": 123}}";
static const char json_no_string_method[] = "{\"id\": 7384,\"method\": 123,\"params\":{\"path\": \"foo/bar/state\",\"value\": 123}}";
static const char json_two_method[] = "[{\"id\": 7384,\"method\": \"add\",\"params\":{\"path\": \"foo/bar/state\",\"value\": 123}}, {\"id\": 7384,\"method\": \"add\",\"params\":{\"path\": \"foo/state\",\"value\": 321}}]";
static const char json_unsupported_method[] = "{\"id\": 7384,\"method\": \"horst\",\"params\":{\"path\": \"foo/bar/state\",\"value\": 123}}";
static const char wrong_jet_array[] = "[1, 2]";
static const char add_without_path[] = "{\"id\": 7384,\"method\": \"add\",\"params\":{\"value\": 123}}";
static const char path_no_string[] = "{\"id\": 7384,\"method\": \"add\",\"params\":{\"path\": 123,\"value\": 123}}";
static const char no_value[] = "{\"id\": 7384,\"method\": \"add\",\"params\":{\"path\": \"foo/bar/state\"}}";
static const char no_params[] = "{\"id\": 7384,\"method\": \"add\"}";

static const int ADD_WITHOUT_PATH = 1;
static const int PATH_NO_STRING = 2;
static const int NO_VALUE = 3;
static const int NO_PARAMS = 4;
static const int UNSUPPORTED_METHOD = 5;

static char readback_buffer[10000];
static char *readback_buffer_ptr = readback_buffer;

extern "C" {

	int fake_read(int fd, void *buf, size_t count)
	{
		return 0;
	}

	int fake_send(int fd, void *buf, size_t count, int flags)
	{
		if (fd == ADD_WITHOUT_PATH) {
			memcpy(readback_buffer_ptr, buf, count);
			readback_buffer_ptr += count;
		}

		if (fd == PATH_NO_STRING) {
			memcpy(readback_buffer_ptr, buf, count);
			readback_buffer_ptr += count;
		}

		if (fd == NO_VALUE) {
			memcpy(readback_buffer_ptr, buf, count);
			readback_buffer_ptr += count;
		}

		if (fd == NO_PARAMS) {
			memcpy(readback_buffer_ptr, buf, count);
			readback_buffer_ptr += count;
		}

		if (fd == UNSUPPORTED_METHOD) {
			memcpy(readback_buffer_ptr, buf, count);
			readback_buffer_ptr += count;
		}
		return count;
	}
}

BOOST_AUTO_TEST_CASE(parse_correct_json)
{
	struct peer *p = alloc_peer(-1);
	create_setter_hashtable();
	int ret = parse_message(correct_json, strlen(correct_json), p);
	BOOST_CHECK(ret == 0);
	free_peer(p);
	delete_setter_hashtable();
}

BOOST_AUTO_TEST_CASE(length_too_long)
{
	int ret = parse_message(correct_json, strlen(correct_json) + 1, NULL);
	BOOST_CHECK(ret == -1);
}

BOOST_AUTO_TEST_CASE(length_too_short)
{
	int ret = parse_message(correct_json, strlen(correct_json) - 1, NULL);
	BOOST_CHECK(ret == -1);
}

BOOST_AUTO_TEST_CASE(parse_wrong_json)
{
	int ret = parse_message(wrong_json, strlen(wrong_json), NULL);
	BOOST_CHECK(ret == -1);
}

BOOST_AUTO_TEST_CASE(no_method)
{
	int ret = parse_message(json_no_method, strlen(json_no_method), NULL);
	BOOST_CHECK(ret == -1);
}

BOOST_AUTO_TEST_CASE(no_string_method)
{
	int ret = parse_message(json_no_string_method, strlen(json_no_string_method), NULL);
	BOOST_CHECK(ret == -1);
}

BOOST_AUTO_TEST_CASE(two_method)
{
	struct peer *p = alloc_peer(-1);
	create_setter_hashtable();
	int ret = parse_message(json_two_method, strlen(json_two_method), p);
	BOOST_CHECK(ret == 0);
	free_peer(p);
	delete_setter_hashtable();
}

BOOST_AUTO_TEST_CASE(wrong_array)
{
	int ret = parse_message(wrong_jet_array, strlen(wrong_jet_array), NULL);
	BOOST_CHECK(ret == -1);
}

BOOST_AUTO_TEST_CASE(add_without_path_test)
{
	readback_buffer_ptr = readback_buffer;
	memset(readback_buffer, 0x00, sizeof(readback_buffer));

	struct peer *p = alloc_peer(ADD_WITHOUT_PATH);
	create_setter_hashtable();
	int ret = parse_message(add_without_path, strlen(add_without_path), p);
	BOOST_CHECK(ret == 0);
	free_peer(p);
	delete_setter_hashtable();

	uint32_t len;
	char *readback_ptr = readback_buffer;
	memcpy(&len, readback_ptr, sizeof(len));
	len = ntohl(len);
	readback_ptr += sizeof(len);

	const char *end_parse;
	cJSON *root = cJSON_ParseWithOpts(readback_ptr, &end_parse, 0);
	BOOST_CHECK(root != NULL);

	uint32_t parsed_length = end_parse - readback_ptr;
	BOOST_CHECK(parsed_length == len);

	cJSON *error = cJSON_GetObjectItem(root, "error");
	BOOST_REQUIRE(error != NULL);

	cJSON *code = cJSON_GetObjectItem(error, "code");
	BOOST_REQUIRE(code != NULL);
	BOOST_CHECK(code->type == cJSON_Number);
	BOOST_CHECK(code->valueint == -32602);

	cJSON *message = cJSON_GetObjectItem(error, "message");
	BOOST_REQUIRE(message != NULL);
	BOOST_CHECK(message->type == cJSON_String);
	BOOST_CHECK(strcmp(message->valuestring, "Invalid params") == 0);

	cJSON_Delete(root);
}

BOOST_AUTO_TEST_CASE(path_no_string_test)
{
	readback_buffer_ptr = readback_buffer;
	memset(readback_buffer, 0x00, sizeof(readback_buffer));

	struct peer *p = alloc_peer(PATH_NO_STRING);
	create_setter_hashtable();
	int ret = parse_message(path_no_string, strlen(path_no_string), p);
	BOOST_CHECK(ret == 0);
	free_peer(p);
	delete_setter_hashtable();

	uint32_t len;
	char *readback_ptr = readback_buffer;
	memcpy(&len, readback_ptr, sizeof(len));
	len = ntohl(len);
	readback_ptr += sizeof(len);

	const char *end_parse;
	cJSON *root = cJSON_ParseWithOpts(readback_ptr, &end_parse, 0);
	BOOST_CHECK(root != NULL);

	uint32_t parsed_length = end_parse - readback_ptr;
	BOOST_CHECK(parsed_length == len);

	cJSON *error = cJSON_GetObjectItem(root, "error");
	BOOST_REQUIRE(error != NULL);

	cJSON *code = cJSON_GetObjectItem(error, "code");
	BOOST_REQUIRE(code != NULL);
	BOOST_CHECK(code->type == cJSON_Number);
	BOOST_CHECK(code->valueint == -32602);

	cJSON *message = cJSON_GetObjectItem(error, "message");
	BOOST_REQUIRE(message != NULL);
	BOOST_CHECK(message->type == cJSON_String);
	BOOST_CHECK(strcmp(message->valuestring, "Invalid params") == 0);

	cJSON_Delete(root);
}

BOOST_AUTO_TEST_CASE(no_value_test)
{
	readback_buffer_ptr = readback_buffer;
	memset(readback_buffer, 0x00, sizeof(readback_buffer));

	struct peer *p = alloc_peer(NO_VALUE);
	create_setter_hashtable();
	int ret = parse_message(no_value, strlen(no_value), p);
	BOOST_CHECK(ret == 0);
	free_peer(p);
	delete_setter_hashtable();

	uint32_t len;
	char *readback_ptr = readback_buffer;
	memcpy(&len, readback_ptr, sizeof(len));
	len = ntohl(len);
	readback_ptr += sizeof(len);

	const char *end_parse;
	cJSON *root = cJSON_ParseWithOpts(readback_ptr, &end_parse, 0);
	BOOST_CHECK(root != NULL);

	uint32_t parsed_length = end_parse - readback_ptr;
	BOOST_CHECK(parsed_length == len);

	cJSON *error = cJSON_GetObjectItem(root, "error");
	BOOST_REQUIRE(error != NULL);

	cJSON *code = cJSON_GetObjectItem(error, "code");
	BOOST_REQUIRE(code != NULL);
	BOOST_CHECK(code->type == cJSON_Number);
	BOOST_CHECK(code->valueint == -32602);

	cJSON *message = cJSON_GetObjectItem(error, "message");
	BOOST_REQUIRE(message != NULL);
	BOOST_CHECK(message->type == cJSON_String);
	BOOST_CHECK(strcmp(message->valuestring, "Invalid params") == 0);

	cJSON_Delete(root);
}

BOOST_AUTO_TEST_CASE(no_params_test)
{
	readback_buffer_ptr = readback_buffer;
	memset(readback_buffer, 0x00, sizeof(readback_buffer));

	struct peer *p = alloc_peer(NO_PARAMS);
	create_setter_hashtable();
	int ret = parse_message(no_params, strlen(no_params), p);
	BOOST_CHECK(ret == 0);
	free_peer(p);
	delete_setter_hashtable();

	uint32_t len;
	char *readback_ptr = readback_buffer;
	memcpy(&len, readback_ptr, sizeof(len));
	len = ntohl(len);
	readback_ptr += sizeof(len);

	const char *end_parse;
	cJSON *root = cJSON_ParseWithOpts(readback_ptr, &end_parse, 0);
	BOOST_CHECK(root != NULL);

	uint32_t parsed_length = end_parse - readback_ptr;
	BOOST_CHECK(parsed_length == len);

	cJSON *error = cJSON_GetObjectItem(root, "error");
	BOOST_REQUIRE(error != NULL);

	cJSON *code = cJSON_GetObjectItem(error, "code");
	BOOST_REQUIRE(code != NULL);
	BOOST_CHECK(code->type == cJSON_Number);
	BOOST_CHECK(code->valueint == -32602);

	cJSON *message = cJSON_GetObjectItem(error, "message");
	BOOST_REQUIRE(message != NULL);
	BOOST_CHECK(message->type == cJSON_String);
	BOOST_CHECK(strcmp(message->valuestring, "Invalid params") == 0);

	cJSON_Delete(root);
}

BOOST_AUTO_TEST_CASE(unsupported_method)
{
	readback_buffer_ptr = readback_buffer;
	memset(readback_buffer, 0x00, sizeof(readback_buffer));

	struct peer *p = alloc_peer(UNSUPPORTED_METHOD);
	create_setter_hashtable();
	int ret = parse_message(json_unsupported_method, strlen(json_unsupported_method), p);
	BOOST_CHECK(ret == 0);
	free_peer(p);
	delete_setter_hashtable();

	uint32_t len;
	char *readback_ptr = readback_buffer;
	memcpy(&len, readback_ptr, sizeof(len));
	len = ntohl(len);
	readback_ptr += sizeof(len);

	const char *end_parse;
	cJSON *root = cJSON_ParseWithOpts(readback_ptr, &end_parse, 0);
	BOOST_CHECK(root != NULL);

	uint32_t parsed_length = end_parse - readback_ptr;
	BOOST_CHECK(parsed_length == len);

	cJSON *error = cJSON_GetObjectItem(root, "error");
	BOOST_REQUIRE(error != NULL);

	cJSON *code = cJSON_GetObjectItem(error, "code");
	BOOST_REQUIRE(code != NULL);
	BOOST_CHECK(code->type == cJSON_Number);
	BOOST_CHECK(code->valueint == -32601);

	cJSON *message = cJSON_GetObjectItem(error, "message");
	BOOST_REQUIRE(message != NULL);
	BOOST_CHECK(message->type == cJSON_String);
	BOOST_CHECK(strcmp(message->valuestring, "Method not found") == 0);

	cJSON_Delete(root);
}

