#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"
#include "compiler.h"
#include "parse.h"
#include "peer.h"
#include "peer_io_ops.h"
#include "response.h"
#include "state.h"

static const char *get_path_from_params(cJSON *params, cJSON **err)
{
	cJSON *path = cJSON_GetObjectItem(params, "path");
	if (unlikely(path == NULL)) {
		cJSON *error = create_invalid_params_error("reason", "no path given");
		*err = error;
		return NULL;
	}
	if (unlikely(path->type != cJSON_String) ) {
		cJSON *error = create_invalid_params_error("reason", "path is not a string");
		*err = error;
		return NULL;
	}
	*err = NULL;
	return path->valuestring;
}

static cJSON *check_for_fetch_id(cJSON *params)
{
	cJSON *id = cJSON_GetObjectItem(params, "id");
	if (unlikely(id == NULL)) {
		return create_invalid_params_error("reason", "no fetch id given");
	}
	if (unlikely((id->type != cJSON_String) && (id->type != cJSON_Number)) ) {
		return create_invalid_params_error("reason", "fetch id is neither string nor number");
	}

	return NULL;
}

static cJSON *process_change(cJSON *params)
{
	cJSON *error;

	const char *path = get_path_from_params(params, &error);
	if (unlikely(path == NULL)) {
		return error;
	}

	cJSON *value = cJSON_GetObjectItem(params, "value");
	if (unlikely(value == NULL) ) {
		error = create_invalid_params_error("reason", "no value given");
		return error;
	}
	error = change_state(path, value);
	return error;
}

static cJSON *process_add(cJSON *params, struct peer *p)
{
	cJSON *error;

	const char *path = get_path_from_params(params, &error);
	if (unlikely(path == NULL)) {
		return error;
	}

	cJSON *value = cJSON_GetObjectItem(params, "value");
	if (unlikely(value == NULL) ) {
		error = create_invalid_params_error("reason", "no value given");
		return error;
	}

	error = add_state_to_peer(p, path, value);
	return error;
}

static cJSON *process_remove(cJSON *params, struct peer *p)
{
	cJSON *error;

	const char *path = get_path_from_params(params, &error);
	if (unlikely(path == NULL)) {
		return error;
	}

	error = remove_state_from_peer(p, path);
	return error;
}

static cJSON *process_fetch(cJSON *params, struct peer *p)
{
	cJSON *error = check_for_fetch_id(params);
	if (unlikely(error != NULL)) {
		return error;
	}
	return NULL;
}

static cJSON *process_config() {
	return NULL;
}

static int possibly_send_response(cJSON *json_rpc, cJSON *error, struct peer *p)
{
	int ret = 0;

	cJSON *id = cJSON_GetObjectItem(json_rpc, "id");
	if (likely(id != NULL)) {
		cJSON *root;
		char *rendered;
		if (unlikely(error != NULL)) {
			root = create_error_response(id, error);
		} else {
			root = create_boolean_success_response(id, TRUE);
		}

		if (unlikely(root == NULL)) {
			if (error != NULL) {
				cJSON_Delete(error);
			}
			return -1;
		}
		rendered = cJSON_PrintUnformatted(root);
		if (unlikely(rendered == NULL)) {
			fprintf(stderr, "Could not render JSON into a string!\n");
			ret = -1;
			goto render_error;
		}
		ret = send_message(p, rendered, strlen(rendered));
		free(rendered);
	render_error:
		cJSON_Delete(root);
	}
	return ret;
}

static int parse_json_rpc(cJSON *json_rpc, struct peer *p)
{
	int ret;
	/* TODO: check if there is a tag "jsonrpc" with value "2.0" */
	cJSON *error = NULL;
	cJSON *method = cJSON_GetObjectItem(json_rpc, "method");

	if (unlikely(method == NULL)) {
		error = create_invalid_request_error("reason", "no method tag found");
		goto no_method;
	}

	if (unlikely(method->type != cJSON_String)) {
		error = create_invalid_request_error("reason", "method tag is not a string");
		goto no_method;
	}

	cJSON *params = cJSON_GetObjectItem(json_rpc, "params");
	if (unlikely(params == NULL)) {
		error = create_invalid_params_error("reason", "no params found");
		goto no_params;
	}

	const char *method_string = method->valuestring;
	if (strcmp(method_string, "change") == 0) {
		error = process_change(params);
	} else if (strcmp(method_string, "set") == 0) {
		error = NULL;
	} else if (strcmp(method_string, "add") == 0) {
		error = process_add(params, p);
	} else if (strcmp(method_string, "remove") == 0) {
		error = process_remove(params, p);
	} else if (strcmp(method_string, "call") == 0) {
		error = NULL;
	} else if (strcmp(method_string, "fetch") == 0) {
		error = process_fetch(params, p);
	} else if (strcmp(method_string, "unfetch") == 0) {
		error = NULL;
	} else if (strcmp(method_string, "config") == 0) {
		error = process_config();
	} else {
		error = create_method_not_found_error("reason", method_string);
		goto unsupported_method;
	}

no_method:
no_params:
unsupported_method:
	ret = possibly_send_response(json_rpc, error, p);

	return ret;
}

int parse_message(char *msg, uint32_t length, struct peer *p)
{
	int ret = 0;

	const char *end_parse;
	cJSON *root = cJSON_ParseWithOpts(msg, &end_parse, 0);
	if (unlikely(root == NULL)) {
		fprintf(stderr, "Could not parse JSON!\n");
		return -1;
	}

	ptrdiff_t parsed_length = end_parse - msg;
	if (unlikely(parsed_length != (ptrdiff_t)length)) {
		fprintf(stderr, "length of parsed JSON (%td) does not match message length (%d)!\n", parsed_length, length);
		ret = -1;
		goto out;
	}

	switch (root->type) {
	case cJSON_Array: {
		unsigned int i;
		unsigned int array_size = cJSON_GetArraySize(root);
		for (i = 0; i < array_size; i++) {
			cJSON *sub_item = cJSON_GetArrayItem(root, i);
			if (likely(sub_item->type == cJSON_Object)) {
				ret = parse_json_rpc(sub_item, p);
				if (unlikely(ret == -1)) {
					goto out;
				}
			} else {
				fprintf(stderr, "JSON is not an object!\n");
				ret = -1;
				goto out;
			}
		}
	}
		break;

	case cJSON_Object:
		ret = parse_json_rpc(root, p);
		break;

	default:
		fprintf(stderr, "JSON is neither array or object!\n");
		ret = -1;
		goto out;
	}

out:
	cJSON_Delete(root);
	return ret;
}
