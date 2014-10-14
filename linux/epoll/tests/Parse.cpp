#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MAIN
#define BOOST_TEST_MODULE parse JSON

#include <arpa/inet.h>
#include <boost/test/unit_test.hpp>
#include <sys/uio.h>

#include <cstring>

#include "cJSON.h"
#include "parse.h"
#include "peer.h"
#include "state.h"

static char wrong_json[] =   "{\"id\": 7384,\"method\": add\",\"params\":{\"path\": \"foo/bar/state\",\"value\": 123}}";
static char json_no_string_method[] = "{\"id\": 7384,\"method\": 123,\"params\":{\"path\": \"foo/bar/state\",\"value\": 123}}";
static char json_unsupported_method[] = "{\"id\": 7384,\"method\": \"horst\",\"params\":{\"path\": \"foo/bar/state\",\"value\": 123}}";
static char add_without_path[] = "{\"id\": 7384,\"method\": \"add\",\"params\":{\"value\": 123}}";
static char remove_without_path[] = "{\"id\": 7384,\"method\": \"remove\",\"params\":{\"value\": 123}}";
static char fetch_without_id[] = "{\"id\": 7384,\"method\": \"fetch\",\"params\":{\"path\": {\"startsWith\": \"person\"}}}";
static char correct_fetch[] = "{\"id\": 7384,\"method\": \"fetch\",\"params\":{\"id\": \"123456\",\"path\": {\"startsWith\": \"person\"}}}";
static char path_no_string[] = "{\"id\": 7384,\"method\": \"add\",\"params\":{\"path\": 123,\"value\": 123}}";
static char no_value[] = "{\"id\": 7384,\"method\": \"add\",\"params\":{\"path\": \"foo/bar/state\"}}";
static char no_params[] = "{\"id\": 7384,\"method\": \"add\"}";

static const int ADD_WITHOUT_PATH = 1;
static const int PATH_NO_STRING = 2;
static const int NO_VALUE = 3;
static const int NO_PARAMS = 4;
static const int UNSUPPORTED_METHOD = 5;
static const int REMOVE_WITHOUT_PATH = 6;
static const int FETCH_WITHOUT_ID = 7;
static const int CORRECT_FETCH = 7;

static char readback_buffer[10000];
static char *readback_buffer_ptr = readback_buffer;

extern "C" {

	int fake_read(int fd, void *buf, size_t count)
	{
		return 0;
	}

	int fake_send(int fd, void *buf, size_t count, int flags)
	{
		return 0;
	}

	static int copy_iov(const struct iovec *iov, int iovcnt)
	{
		int count = 0;
		for (int i = 0; i < iovcnt; ++i) {
			memcpy(readback_buffer_ptr, iov[i].iov_base, iov[i].iov_len);
			readback_buffer_ptr += iov[i].iov_len;
			count += iov[i].iov_len;
		}
		return count;
	}

	int fake_writev(int fd, const struct iovec *iov, int iovcnt)
	{
		int count = copy_iov(iov, iovcnt);
		return count;
	}
}

struct F {
	F(int fd)
	{
		create_state_hashtable();
		p = alloc_peer(fd);

		readback_buffer_ptr = readback_buffer;
		std::memset(readback_buffer, 0x00, sizeof(readback_buffer));
	}
	~F()
	{
		free_peer(p);
		delete_state_hashtable();
	}

	struct peer *p;
};

static void check_invalid_message(const char *buffer, int code, const char *message_string)
{
	uint32_t len;
	const char *readback_ptr = buffer;
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

	cJSON *code_object = cJSON_GetObjectItem(error, "code");
	BOOST_REQUIRE(code_object != NULL);
	BOOST_CHECK(code_object->type == cJSON_Number);
	BOOST_CHECK(code_object->valueint == code);

	cJSON *message = cJSON_GetObjectItem(error, "message");
	BOOST_REQUIRE(message != NULL);
	BOOST_CHECK(message->type == cJSON_String);
	BOOST_CHECK(strcmp(message->valuestring, message_string) == 0);

	cJSON_Delete(root);
}

static void check_invalid_params_message(const char *buffer)
{
	check_invalid_message(buffer, -32602, "Invalid params");
}

static void check_method_not_found_message(const char *buffer)
{
	check_invalid_message(buffer, -32601, "Method not found");
}

static cJSON *create_correct_json()
{
	cJSON *root = cJSON_CreateObject();
	cJSON_AddNumberToObject(root, "id", 7384);
	cJSON_AddStringToObject(root, "method", "add");

	cJSON *params = cJSON_CreateObject();
	cJSON_AddStringToObject(params, "path", "/foo/bar/state/");
	cJSON_AddNumberToObject(params, "value", 123);
	cJSON_AddItemToObject(root, "params", params);
	return root;
}

static cJSON *create_two_method_json()
{
	cJSON *array = cJSON_CreateArray();
	cJSON *method_1 = create_correct_json();
	cJSON *method_2 = create_correct_json();
	cJSON_AddItemToArray(array, method_1);
	cJSON_AddItemToArray(array, method_2);
	return array;
}

static cJSON *create_json_no_method()
{
	cJSON *root = cJSON_CreateObject();
	cJSON_AddNumberToObject(root, "id", 7384);
	cJSON_AddStringToObject(root, "meth", "add");

	cJSON *params = cJSON_CreateObject();
	cJSON_AddStringToObject(params, "path", "/foo/bar/state/");
	cJSON_AddNumberToObject(params, "value", 123);
	cJSON_AddItemToObject(root, "params", params);
	return root;
}

static void check_invalid_request_message(const char *buffer)
{
	check_invalid_message(buffer, -32600, "Invalid Request");
}

BOOST_AUTO_TEST_CASE(parse_correct_json)
{
	F f(-1);
	cJSON *correct_json = create_correct_json();
	char *unformatted_json = cJSON_PrintUnformatted(correct_json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), f.p);
	cJSON_free(unformatted_json);
	cJSON_Delete(correct_json);
	BOOST_CHECK(ret == 0);
}

BOOST_AUTO_TEST_CASE(length_too_long)
{
	cJSON *correct_json = create_correct_json();
	char *unformatted_json = cJSON_PrintUnformatted(correct_json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json) + 1, NULL);
	cJSON_free(unformatted_json);
	cJSON_Delete(correct_json);

	BOOST_CHECK(ret == -1);
}

BOOST_AUTO_TEST_CASE(length_too_short)
{
	cJSON *correct_json = create_correct_json();
	char *unformatted_json = cJSON_PrintUnformatted(correct_json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json) - 1, NULL);
	cJSON_free(unformatted_json);
	cJSON_Delete(correct_json);

	BOOST_CHECK(ret == -1);
}

BOOST_AUTO_TEST_CASE(two_method)
{
	F f(-1);
	cJSON *array = create_two_method_json();
	char *unformatted_json = cJSON_PrintUnformatted(array);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), f.p);
	cJSON_free(unformatted_json);
	cJSON_Delete(array);
	BOOST_CHECK(ret == 0);
}

BOOST_AUTO_TEST_CASE(wrong_array)
{
	const int numbers[2] = {1,2};
	cJSON *root = cJSON_CreateIntArray(numbers, 2);
	char *unformatted_json = cJSON_PrintUnformatted(root);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), NULL);
	cJSON_free(unformatted_json);
	cJSON_Delete(root);

	BOOST_CHECK(ret == -1);
}

BOOST_AUTO_TEST_CASE(add_without_path_test)
{
	F f(ADD_WITHOUT_PATH);
	int ret = parse_message(add_without_path, strlen(add_without_path), f.p);
	BOOST_CHECK(ret == 0);

	check_invalid_params_message(readback_buffer);
}

BOOST_AUTO_TEST_CASE(path_no_string_test)
{
	F f(PATH_NO_STRING);
	int ret = parse_message(path_no_string, strlen(path_no_string), f.p);
	BOOST_CHECK(ret == 0);

	check_invalid_params_message(readback_buffer);
}

BOOST_AUTO_TEST_CASE(no_value_test)
{
	F f(NO_VALUE);
	int ret = parse_message(no_value, strlen(no_value), f.p);
	BOOST_CHECK(ret == 0);

	check_invalid_params_message(readback_buffer);
}

BOOST_AUTO_TEST_CASE(no_params_test)
{
	F f(NO_PARAMS);
	int ret = parse_message(no_params, strlen(no_params), f.p);
	BOOST_CHECK(ret == 0);

	check_invalid_params_message(readback_buffer);
}

BOOST_AUTO_TEST_CASE(unsupported_method)
{
	F f(UNSUPPORTED_METHOD);
	int ret = parse_message(json_unsupported_method, strlen(json_unsupported_method), f.p);
	BOOST_CHECK(ret == 0);

	check_method_not_found_message(readback_buffer);
}

BOOST_AUTO_TEST_CASE(no_method)
{
	F f(UNSUPPORTED_METHOD);
	cJSON *json = create_json_no_method();
	char *unformatted_json = cJSON_PrintUnformatted(json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), f.p);
	cJSON_free(unformatted_json);
	cJSON_Delete(json);
	BOOST_CHECK(ret == 0);

	check_invalid_request_message(readback_buffer);
}


BOOST_AUTO_TEST_CASE(no_string_method)
{
	F f(UNSUPPORTED_METHOD);
	int ret = parse_message(json_no_string_method, strlen(json_no_string_method), f.p);
	BOOST_CHECK(ret == 0);

	check_invalid_request_message(readback_buffer);
}

BOOST_AUTO_TEST_CASE(parse_wrong_json)
{
	int ret = parse_message(wrong_json, strlen(wrong_json), NULL);
	BOOST_CHECK(ret == -1);
}

BOOST_AUTO_TEST_CASE(remove_without_path_test)
{
	F f(REMOVE_WITHOUT_PATH);
	int ret = parse_message(remove_without_path, strlen(remove_without_path), f.p);
	BOOST_CHECK(ret == 0);

	check_invalid_params_message(readback_buffer);
}

BOOST_AUTO_TEST_CASE(fetch_without_id_test)
{
	F f(FETCH_WITHOUT_ID);
	int ret = parse_message(fetch_without_id, strlen(fetch_without_id), f.p);
	BOOST_CHECK(ret == 0);

	check_invalid_params_message(readback_buffer);
}

BOOST_AUTO_TEST_CASE(correct_fetch_test)
{
	F f(CORRECT_FETCH);
	int ret = parse_message(correct_fetch, strlen(correct_fetch), f.p);
	BOOST_CHECK(ret == 0);
}
