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
		if (strcmp(path, "method") == 0) {
			return 0;
		}
		return -1;
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


	int remove_state_from_peer(struct peer *p, const char *path)
	{
		if (strcmp(path, "state") == 0) {
			return 0;
		}
		return -1;
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

	void log_peer_err(const struct peer *p, const char *fmt, ...)
	{
	}

	void set_peer_name(struct peer *peer, const char *name)
	{
	}
}

struct F {
	F()
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

static cJSON *create_correct_add_state()
{
	cJSON *root = cJSON_CreateObject();
	BOOST_REQUIRE(root != NULL);
	cJSON_AddNumberToObject(root, "id", 7384);
	cJSON_AddStringToObject(root, "method", "add");

	cJSON *params = cJSON_CreateObject();
	BOOST_REQUIRE(params != NULL);
	cJSON_AddStringToObject(params, "path", "/foo/bar/state/");
	cJSON_AddNumberToObject(params, "value", 123);
	cJSON_AddItemToObject(root, "params", params);
	return root;
}

static cJSON *create_correct_add_method()
{
	cJSON *root = cJSON_CreateObject();
	BOOST_REQUIRE(root != NULL);
	cJSON_AddNumberToObject(root, "id", 7384);
	cJSON_AddStringToObject(root, "method", "add");

	cJSON *params = cJSON_CreateObject();
	BOOST_REQUIRE(params != NULL);
	cJSON_AddStringToObject(params, "path", "/foo/bar/state/");
	cJSON_AddItemToObject(root, "params", params);
	return root;
}

static cJSON *create_correct_config_method()
{
	cJSON *root = cJSON_CreateObject();
	BOOST_REQUIRE(root != NULL);
	cJSON_AddNumberToObject(root, "id", 7384);
	cJSON_AddStringToObject(root, "method", "config");

	cJSON *params = cJSON_CreateObject();
	BOOST_REQUIRE(params != NULL);
	cJSON_AddItemToObject(root, "params", params);
	return root;
}

static cJSON *create_two_method_json()
{
	cJSON *array = cJSON_CreateArray();
	BOOST_REQUIRE(array != NULL);
	cJSON *method_1 = create_correct_add_state();
	cJSON *method_2 = create_correct_add_state();
	cJSON_AddItemToArray(array, method_1);
	cJSON_AddItemToArray(array, method_2);
	return array;
}

static cJSON *create_json_no_method()
{
	cJSON *root = cJSON_CreateObject();
	BOOST_REQUIRE(root != NULL);
	cJSON_AddNumberToObject(root, "id", 7384);
	cJSON_AddStringToObject(root, "meth", "add");

	cJSON *params = cJSON_CreateObject();
	BOOST_REQUIRE(params != NULL);
	cJSON_AddStringToObject(params, "path", "/foo/bar/state/");
	cJSON_AddNumberToObject(params, "value", 123);
	cJSON_AddItemToObject(root, "params", params);
	return root;
}

static cJSON *create_result_json()
{
	cJSON *root = cJSON_CreateObject();
	BOOST_REQUIRE(root != NULL);
	cJSON_AddNumberToObject(root, "id", 7384);
	cJSON *result = cJSON_CreateObject();
	BOOST_REQUIRE(result != NULL);
	cJSON_AddItemToObject(root, "result", result);
	return root;
}

static cJSON *create_error_json()
{
	cJSON *root = cJSON_CreateObject();
	BOOST_REQUIRE(root != NULL);
	cJSON_AddNumberToObject(root, "id", 7384);
	cJSON *error = cJSON_CreateObject();
	BOOST_REQUIRE(error != NULL);
	cJSON_AddItemToObject(root, "error", error);
	return root;
}

static cJSON *create_json_no_string_method()
{
	cJSON *root = cJSON_CreateObject();
	BOOST_REQUIRE(root != NULL);
	cJSON_AddNumberToObject(root, "id", 7384);
	cJSON_AddNumberToObject(root, "method", 123);

	cJSON *params = cJSON_CreateObject();
	BOOST_REQUIRE(params != NULL);
	cJSON_AddStringToObject(params, "path", "/foo/bar/state/");
	cJSON_AddNumberToObject(params, "value", 123);
	cJSON_AddItemToObject(root, "params", params);
	return root;
}

static cJSON *create_json_unsupported_method()
{
	cJSON *root = cJSON_CreateObject();
	BOOST_REQUIRE(root != NULL);
	cJSON_AddNumberToObject(root, "id", 7384);
	cJSON_AddStringToObject(root, "method", "horst");

	cJSON *params = cJSON_CreateObject();
	BOOST_REQUIRE(params != NULL);
	cJSON_AddStringToObject(params, "path", "/foo/bar/state/");
	cJSON_AddNumberToObject(params, "value", 123);
	cJSON_AddItemToObject(root, "params", params);
	return root;
}

static cJSON *create_add_without_path()
{
	cJSON *root = cJSON_CreateObject();
	BOOST_REQUIRE(root != NULL);
	cJSON_AddNumberToObject(root, "id", 7384);
	cJSON_AddStringToObject(root, "method", "add");

	cJSON *params = cJSON_CreateObject();
	BOOST_REQUIRE(params != NULL);
	cJSON_AddNumberToObject(params, "value", 123);
	cJSON_AddItemToObject(root, "params", params);
	return root;
}

static cJSON *create_correct_remove(const char *what)
{
	cJSON *root = cJSON_CreateObject();
	BOOST_REQUIRE(root != NULL);
	cJSON_AddNumberToObject(root, "id", 7384);
	cJSON_AddStringToObject(root, "method", "remove");

	cJSON *params = cJSON_CreateObject();
	BOOST_REQUIRE(params != NULL);
	cJSON_AddStringToObject(params, "path", what);
	cJSON_AddItemToObject(root, "params", params);
	return root;
}

static cJSON *create_remove_without_path()
{
	cJSON *root = cJSON_CreateObject();
	BOOST_REQUIRE(root != NULL);
	cJSON_AddNumberToObject(root, "id", 7384);
	cJSON_AddStringToObject(root, "method", "remove");

	cJSON *params = cJSON_CreateObject();
	BOOST_REQUIRE(params != NULL);
	cJSON_AddItemToObject(root, "params", params);
	return root;
}

static cJSON *create_path_no_string()
{
	cJSON *root = cJSON_CreateObject();
	BOOST_REQUIRE(root != NULL);
	cJSON_AddNumberToObject(root, "id", 7384);
	cJSON_AddStringToObject(root, "method", "add");

	cJSON *params = cJSON_CreateObject();
	BOOST_REQUIRE(params != NULL);
	cJSON_AddNumberToObject(params, "path", 123);
	cJSON_AddNumberToObject(params, "value", 123);
	cJSON_AddItemToObject(root, "params", params);
	return root;
}

static cJSON *create_json_no_params()
{
	cJSON *root = cJSON_CreateObject();
	BOOST_REQUIRE(root != NULL);
	cJSON_AddNumberToObject(root, "id", 7384);
	cJSON_AddStringToObject(root, "method", "add");
	return root;
}

static cJSON *create_correct_fetch()
{
	cJSON *root = cJSON_CreateObject();
	BOOST_REQUIRE(root != NULL);
	cJSON_AddNumberToObject(root, "id", 7384);
	cJSON_AddStringToObject(root, "method", "fetch");

	cJSON *params = cJSON_CreateObject();
	BOOST_REQUIRE(params != NULL);
	cJSON_AddStringToObject(params, "id", "123456");
	cJSON_AddItemToObject(root, "params", params);

	cJSON *path = cJSON_CreateObject();
	BOOST_REQUIRE(path != NULL);
	cJSON_AddStringToObject(path, "equals", "person");
	cJSON_AddStringToObject(path, "startsWith", "per");
	cJSON_AddItemToObject(params, "path", path);
	return root;
}

static cJSON *create_fetch_without_id()
{
	cJSON *root = cJSON_CreateObject();
	BOOST_REQUIRE(root != NULL);
	cJSON_AddNumberToObject(root, "id", 7384);
	cJSON_AddStringToObject(root, "method", "fetch");

	cJSON *params = cJSON_CreateObject();
	BOOST_REQUIRE(params != NULL);
	cJSON_AddItemToObject(root, "params", params);

	cJSON *path = cJSON_CreateObject();
	BOOST_REQUIRE(path != NULL);
	cJSON_AddStringToObject(path, "startsWith", "person");
	cJSON_AddItemToObject(params, "path", path);
	return root;
}

static cJSON *create_correct_unfetch()
{
	cJSON *root = cJSON_CreateObject();
	BOOST_REQUIRE(root != NULL);
	cJSON_AddNumberToObject(root, "id", 7384);
	cJSON_AddStringToObject(root, "method", "unfetch");

	cJSON *params = cJSON_CreateObject();
	BOOST_REQUIRE(params != NULL);
	cJSON_AddStringToObject(params, "id", "123456");
	cJSON_AddItemToObject(root, "params", params);
	return root;
}

static void check_invalid_params_error(void)
{
	char *ptr = readback_buffer;
	ptr += 4;
	cJSON *root = cJSON_Parse(ptr);
	BOOST_REQUIRE(root != NULL);

	cJSON *error = cJSON_GetObjectItem(root, "error");
	BOOST_REQUIRE(error != NULL);

	cJSON *code = cJSON_GetObjectItem(error, "code");
	if (code != NULL) {
		BOOST_REQUIRE(code->type == cJSON_Number);
		BOOST_CHECK(code->valueint == -32602);
	} else {
		BOOST_FAIL("No code object!");
	}
	cJSON_Delete(root);
}

BOOST_AUTO_TEST_CASE(parse_correct_json)
{
	F f;
	cJSON *correct_json = create_correct_add_state();
	char *unformatted_json = cJSON_PrintUnformatted(correct_json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), f.p);
	cJSON_free(unformatted_json);
	cJSON_Delete(correct_json);
	BOOST_CHECK(ret == 0);
}

BOOST_AUTO_TEST_CASE(length_too_long)
{
	if (CONFIG_CHECK_JSON_LENGTH) {
		cJSON *correct_json = create_correct_add_state();
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
		cJSON *correct_json = create_correct_add_state();
		char *unformatted_json = cJSON_PrintUnformatted(correct_json);
		int ret = parse_message(unformatted_json, strlen(unformatted_json) - 1, NULL);
		cJSON_free(unformatted_json);
		cJSON_Delete(correct_json);

		BOOST_CHECK(ret == -1);
	}
}

BOOST_AUTO_TEST_CASE(two_method)
{
	F f;
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
	F f;

	cJSON *json = create_add_without_path();
	char *unformatted_json = cJSON_PrintUnformatted(json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), f.p);
	cJSON_free(unformatted_json);
	cJSON_Delete(json);
	BOOST_CHECK(ret == 0);
}

BOOST_AUTO_TEST_CASE(correct_remove_state_test)
{
	F f;
	cJSON *json = create_correct_remove("state");
	char *unformatted_json = cJSON_PrintUnformatted(json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), f.p);
	cJSON_free(unformatted_json);
	cJSON_Delete(json);
	BOOST_CHECK(ret == 0);
}

BOOST_AUTO_TEST_CASE(correct_add_method_test)
{
	F f;
	cJSON *correct_json = create_correct_add_method();
	char *unformatted_json = cJSON_PrintUnformatted(correct_json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), f.p);
	cJSON_free(unformatted_json);
	cJSON_Delete(correct_json);
	BOOST_CHECK(ret == 0);
}

BOOST_AUTO_TEST_CASE(correct_remove_method_test)
{
	F f;
	cJSON *json = create_correct_remove("method");
	char *unformatted_json = cJSON_PrintUnformatted(json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), f.p);
	cJSON_free(unformatted_json);
	cJSON_Delete(json);
	BOOST_CHECK(ret == 0);
}

BOOST_AUTO_TEST_CASE(remove_non_existing_state_or_method)
{
	F f;
	cJSON *json = create_correct_remove("non_exist");
	char *unformatted_json = cJSON_PrintUnformatted(json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), f.p);
	cJSON_free(unformatted_json);
	cJSON_Delete(json);
	BOOST_CHECK(ret == 0);
	check_invalid_params_error();
}

BOOST_AUTO_TEST_CASE(remove_without_path_test)
{
	F f;
	cJSON *json = create_remove_without_path();
	char *unformatted_json = cJSON_PrintUnformatted(json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), f.p);
	cJSON_free(unformatted_json);
	cJSON_Delete(json);
	BOOST_CHECK(ret == 0);
}

BOOST_AUTO_TEST_CASE(path_no_string_test)
{
	F f;
	cJSON *json = create_path_no_string();
	char *unformatted_json = cJSON_PrintUnformatted(json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), f.p);
	cJSON_free(unformatted_json);
	cJSON_Delete(json);
	BOOST_CHECK(ret == 0);
}

BOOST_AUTO_TEST_CASE(no_params_test)
{
	F f;

	cJSON *json = create_json_no_params();
	char *unformatted_json = cJSON_PrintUnformatted(json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), f.p);
	cJSON_free(unformatted_json);
	cJSON_Delete(json);
	BOOST_CHECK(ret == 0);
}

BOOST_AUTO_TEST_CASE(unsupported_method)
{
	F f;

	cJSON *json = create_json_unsupported_method();
	char *unformatted_json = cJSON_PrintUnformatted(json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), f.p);
	cJSON_free(unformatted_json);
	cJSON_Delete(json);
	BOOST_CHECK(ret == 0);
}

BOOST_AUTO_TEST_CASE(no_method)
{
	F f;
	cJSON *json = create_json_no_method();
	char *unformatted_json = cJSON_PrintUnformatted(json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), f.p);
	cJSON_free(unformatted_json);
	cJSON_Delete(json);
	BOOST_CHECK(ret == 0);
}

BOOST_AUTO_TEST_CASE(no_string_method)
{
	F f;
	cJSON *json = create_json_no_string_method();
	char *unformatted_json = cJSON_PrintUnformatted(json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), f.p);
	cJSON_free(unformatted_json);
	cJSON_Delete(json);
	BOOST_CHECK(ret == 0);
}

BOOST_AUTO_TEST_CASE(test_result_rpc)
{
	F f;
	cJSON *json = create_result_json();
	char *unformatted_json = cJSON_PrintUnformatted(json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), f.p);
	cJSON_free(unformatted_json);
	cJSON_Delete(json);
	BOOST_CHECK(ret == 0);
}

BOOST_AUTO_TEST_CASE(test_error_rpc)
{
	F f;
	cJSON *json = create_error_json();
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
	F f;
	cJSON *json = create_fetch_without_id();
	char *unformatted_json = cJSON_PrintUnformatted(json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), f.p);
	cJSON_free(unformatted_json);
	cJSON_Delete(json);
	BOOST_CHECK(ret == 0);
}

BOOST_AUTO_TEST_CASE(correct_fetch_test)
{
	F f;
	cJSON *json = create_correct_fetch();
	char *unformatted_json = cJSON_PrintUnformatted(json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), f.p);
	cJSON_free(unformatted_json);
	cJSON_Delete(json);
	BOOST_CHECK(ret == 0);
}

BOOST_AUTO_TEST_CASE(correct_unfetch_test)
{
	F f;
	cJSON *json = create_correct_unfetch();
	char *unformatted_json = cJSON_PrintUnformatted(json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), f.p);
	cJSON_free(unformatted_json);
	cJSON_Delete(json);
	BOOST_CHECK(ret == 0);
}

BOOST_AUTO_TEST_CASE(correct_config_test)
{
	F f;
	cJSON *json = create_correct_config_method();

	char *unformatted_json = cJSON_PrintUnformatted(json);
	int ret = parse_message(unformatted_json, strlen(unformatted_json), f.p);
	cJSON_free(unformatted_json);
	cJSON_Delete(json);
	BOOST_CHECK(ret == 0);
}

BOOST_AUTO_TEST_CASE(correct_change)
{
	F f;
}
