#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MAIN
#define BOOST_TEST_MODULE parse JSON

#include <arpa/inet.h>
#include <boost/test/unit_test.hpp>
#include <sys/uio.h>

#include <cstring>

#include "config/config.h"
#include "json/cJSON.h"
#include "parse.h"
#include "peer.h"
#include "state.h"

static const int ADD_WITHOUT_PATH = 1;
static const int PATH_NO_STRING = 2;
static const int NO_VALUE = 3;
static const int NO_PARAMS = 4;
static const int UNSUPPORTED_METHOD = 5;
static const int REMOVE_WITHOUT_PATH = 6;
static const int FETCH_WITHOUT_ID = 7;
static const int CORRECT_FETCH = 8;
static const int CORRECT_CHANGE = 9;
static const int REMOVE = 10;

static char readback_buffer[10000];
static char *readback_buffer_ptr = readback_buffer;

extern "C" {
	int send_message(struct peer *p, const char *rendered, size_t len)
	{
		char *ptr = readback_buffer;
		uint32_t message_length = htonl(len);
		memcpy(ptr, &message_length, sizeof(message_length));
		ptr += 4;
		memcpy(ptr, rendered, len);
		return 0;
	}

	cJSON *remove_fetch_from_peer(struct peer *p, cJSON *params)
	{
		return NULL;
	}

	cJSON *add_fetch_to_peer(struct peer *p, cJSON *params,
		struct fetch **fetch_return)
	{
		return NULL;
	}

	int add_fetch_to_states(struct fetch *f)
	{
		return 0;
	}

	int remove_method_from_peer(struct peer *p, const char *path)
	{
		return 0;
	}

	cJSON *add_method_to_peer(struct peer *p, const char *path)
	{
		return NULL;
	}

	int handle_routing_response(cJSON *json_rpc, cJSON *response,
		const struct peer *p)
	{
		return 0;
	}

	cJSON *call_method(struct peer *p, const char *path,
		cJSON *args, cJSON *json_rpc)
	{
		return NULL;
	}

	cJSON *create_invalid_params_error(const char *tag, const char *reason)
	{
		return NULL;
	}

	cJSON *create_boolean_success_response(const cJSON *id, int true_false)
	{
		cJSON *boolean;
		if (true_false == 0) {
			boolean = cJSON_CreateFalse();
		} else {
			boolean = cJSON_CreateTrue();
		}
		return boolean;
	}

	cJSON *create_error_response(const cJSON *id, cJSON *error)
	{
		return NULL;
	}

	int remove_state_from_peer(struct peer *p, const char *path)
	{
		return 0;
	}

	cJSON *add_state_to_peer(struct peer *p, const char *path, cJSON *value)
	{
		return NULL;
	}

	cJSON *set_state(struct peer *p, const char *path,
		cJSON *value, cJSON *json_rpc)
	{
		return NULL;
	}

	cJSON *change_state(struct peer *p, const char *path, cJSON *value)
	{
		return NULL;
	}

	cJSON *create_method_not_found_error(const char *tag, const char *reason)
	{
		return NULL;
	}

	cJSON *create_invalid_request_error(const char *tag, const char *reason)
	{
		return NULL;
	}
}

struct F {
	F(int fd)
	{
		p = NULL;

		readback_buffer_ptr = readback_buffer;
		std::memset(readback_buffer, 0x00, sizeof(readback_buffer));
	}

	~F()
	{
	}

	struct peer *p;
};

static cJSON *create_correct_add()
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
	cJSON *method_1 = create_correct_add();
	cJSON *method_2 = create_correct_add();
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

static cJSON *create_json_no_string_method()
{
	cJSON *root = cJSON_CreateObject();
	cJSON_AddNumberToObject(root, "id", 7384);
	cJSON_AddNumberToObject(root, "method", 123);

	cJSON *params = cJSON_CreateObject();
	cJSON_AddStringToObject(params, "path", "/foo/bar/state/");
	cJSON_AddNumberToObject(params, "value", 123);
	cJSON_AddItemToObject(root, "params", params);
	return root;
}

static cJSON *create_json_unsupported_method()
{
	cJSON *root = cJSON_CreateObject();
	cJSON_AddNumberToObject(root, "id", 7384);
	cJSON_AddStringToObject(root, "method", "horst");

	cJSON *params = cJSON_CreateObject();
	cJSON_AddStringToObject(params, "path", "/foo/bar/state/");
	cJSON_AddNumberToObject(params, "value", 123);
	cJSON_AddItemToObject(root, "params", params);
	return root;
}

static cJSON *create_add_without_path()
{
	cJSON *root = cJSON_CreateObject();
	cJSON_AddNumberToObject(root, "id", 7384);
	cJSON_AddStringToObject(root, "method", "add");

	cJSON *params = cJSON_CreateObject();
	cJSON_AddNumberToObject(params, "value", 123);
	cJSON_AddItemToObject(root, "params", params);
	return root;
}

static cJSON *create_correct_remove()
{
	cJSON *root = cJSON_CreateObject();
	cJSON_AddNumberToObject(root, "id", 7384);
	cJSON_AddStringToObject(root, "method", "remove");

	cJSON *params = cJSON_CreateObject();
	cJSON_AddStringToObject(params, "path", "/foo/bar/state/");
	cJSON_AddItemToObject(root, "params", params);
	return root;
}

static cJSON *create_remove_without_path()
{
	cJSON *root = cJSON_CreateObject();
	cJSON_AddNumberToObject(root, "id", 7384);
	cJSON_AddStringToObject(root, "method", "remove");

	cJSON *params = cJSON_CreateObject();
	cJSON_AddItemToObject(root, "params", params);
	return root;
}

static cJSON *create_path_no_string()
{
	cJSON *root = cJSON_CreateObject();
	cJSON_AddNumberToObject(root, "id", 7384);
	cJSON_AddStringToObject(root, "method", "add");

	cJSON *params = cJSON_CreateObject();
	cJSON_AddNumberToObject(params, "path", 123);
	cJSON_AddNumberToObject(params, "value", 123);
	cJSON_AddItemToObject(root, "params", params);
	return root;
}

static cJSON *create_json_no_params()
{
	cJSON *root = cJSON_CreateObject();
	cJSON_AddNumberToObject(root, "id", 7384);
	cJSON_AddStringToObject(root, "method", "add");
	return root;
}

static cJSON *create_correct_fetch()
{
	cJSON *root = cJSON_CreateObject();
	cJSON_AddNumberToObject(root, "id", 7384);
	cJSON_AddStringToObject(root, "method", "fetch");

	cJSON *params = cJSON_CreateObject();
	cJSON_AddStringToObject(params, "id", "123456");
	cJSON_AddItemToObject(root, "params", params);

	cJSON *path = cJSON_CreateObject();
	cJSON_AddStringToObject(path, "equals", "person");
	cJSON_AddStringToObject(path, "startsWith", "per");
	cJSON_AddItemToObject(params, "path", path);
	return root;
}

static cJSON *create_fetch_without_id()
{
	cJSON *root = cJSON_CreateObject();
	cJSON_AddNumberToObject(root, "id", 7384);
	cJSON_AddStringToObject(root, "method", "fetch");

	cJSON *params = cJSON_CreateObject();
	cJSON_AddItemToObject(root, "params", params);

	cJSON *path = cJSON_CreateObject();
	cJSON_AddStringToObject(path, "startsWith", "person");
	cJSON_AddItemToObject(params, "path", path);
	return root;
}

BOOST_AUTO_TEST_CASE(parse_correct_json)
{
	F f(-1);
	cJSON *correct_json = create_correct_add();
	char *unformatted_json = cJSON_PrintUnformatted(correct_json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), f.p);
	cJSON_free(unformatted_json);
	cJSON_Delete(correct_json);
	BOOST_CHECK(ret == 0);
}

BOOST_AUTO_TEST_CASE(length_too_long)
{
	if (CONFIG_CHECK_JSON_LENGTH) {
		cJSON *correct_json = create_correct_add();
		char *unformatted_json = cJSON_PrintUnformatted(correct_json);
		int ret = parse_message(unformatted_json, strlen(unformatted_json) + 1, NULL);
		cJSON_free(unformatted_json);
		cJSON_Delete(correct_json);

		BOOST_CHECK(ret == -1);
	}
}

BOOST_AUTO_TEST_CASE(length_too_short)
{
	if (CONFIG_CHECK_JSON_LENGTH) {
		cJSON *correct_json = create_correct_add();
		char *unformatted_json = cJSON_PrintUnformatted(correct_json);
		int ret = parse_message(unformatted_json, strlen(unformatted_json) - 1, NULL);
		cJSON_free(unformatted_json);
		cJSON_Delete(correct_json);

		BOOST_CHECK(ret == -1);
	}
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

	cJSON *json = create_add_without_path();
	char *unformatted_json = cJSON_PrintUnformatted(json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), f.p);
	cJSON_free(unformatted_json);
	cJSON_Delete(json);
	BOOST_CHECK(ret == 0);
}

BOOST_AUTO_TEST_CASE(correct_remove_test)
{
	F f(REMOVE);
	cJSON *json = create_correct_remove();
	char *unformatted_json = cJSON_PrintUnformatted(json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), f.p);
	cJSON_free(unformatted_json);
	cJSON_Delete(json);
	BOOST_CHECK(ret == 0);
}

BOOST_AUTO_TEST_CASE(remove_without_path_test)
{
	F f(REMOVE_WITHOUT_PATH);
	cJSON *json = create_remove_without_path();
	char *unformatted_json = cJSON_PrintUnformatted(json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), f.p);
	cJSON_free(unformatted_json);
	cJSON_Delete(json);
	BOOST_CHECK(ret == 0);
}

BOOST_AUTO_TEST_CASE(path_no_string_test)
{
	F f(PATH_NO_STRING);
	cJSON *json = create_path_no_string();
	char *unformatted_json = cJSON_PrintUnformatted(json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), f.p);
	cJSON_free(unformatted_json);
	cJSON_Delete(json);
	BOOST_CHECK(ret == 0);
}

BOOST_AUTO_TEST_CASE(no_params_test)
{
	F f(NO_PARAMS);

	cJSON *json = create_json_no_params();
	char *unformatted_json = cJSON_PrintUnformatted(json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), f.p);
	cJSON_free(unformatted_json);
	cJSON_Delete(json);
	BOOST_CHECK(ret == 0);
}

BOOST_AUTO_TEST_CASE(unsupported_method)
{
	F f(UNSUPPORTED_METHOD);

	cJSON *json = create_json_unsupported_method();
	char *unformatted_json = cJSON_PrintUnformatted(json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), f.p);
	cJSON_free(unformatted_json);
	cJSON_Delete(json);
	BOOST_CHECK(ret == 0);
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
}


BOOST_AUTO_TEST_CASE(no_string_method)
{
	F f(UNSUPPORTED_METHOD);
	cJSON *json = create_json_no_string_method();
	char *unformatted_json = cJSON_PrintUnformatted(json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), f.p);
	cJSON_free(unformatted_json);
	cJSON_Delete(json);
	BOOST_CHECK(ret == 0);
}

BOOST_AUTO_TEST_CASE(parse_wrong_json)
{
	static const char wrong_json[] =   "{\"id\": 7384,\"method\": add\",\"params\":{\"path\": \"foo/bar/state\",\"value\": 123}}";
	int ret = parse_message(wrong_json, strlen(wrong_json), NULL);
	BOOST_CHECK(ret == -1);
}

BOOST_AUTO_TEST_CASE(parse_json_no_object_or_array)
{
	static const char json[] = "\"foo\"";
	int ret = parse_message(json, strlen(json), NULL);
	BOOST_CHECK(ret == -1);
}

BOOST_AUTO_TEST_CASE(fetch_without_id_test)
{
	F f(FETCH_WITHOUT_ID);
	cJSON *json = create_fetch_without_id();
	char *unformatted_json = cJSON_PrintUnformatted(json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), f.p);
	cJSON_free(unformatted_json);
	cJSON_Delete(json);
	BOOST_CHECK(ret == 0);
}

BOOST_AUTO_TEST_CASE(correct_fetch_test)
{
	F f(CORRECT_FETCH);
	cJSON *json = create_correct_fetch();
	char *unformatted_json = cJSON_PrintUnformatted(json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), f.p);
	cJSON_free(unformatted_json);
	cJSON_Delete(json);
	BOOST_CHECK(ret == 0);
}

BOOST_AUTO_TEST_CASE(correct_change)
{
	F f(CORRECT_CHANGE);
}
