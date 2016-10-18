/*
 *The MIT License (MIT)
 *
 * Copyright (c) <2014> <Stephan Gatzka>
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

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "alloc.h"
#include "compiler.h"
#include "config.h"
#include "fetch.h"
#include "generated/cjet_config.h"
#include "info.h"
#include "json/cJSON.h"
#include "linux/linux_io.h"
#include "parse.h"
#include "peer.h"
#include "response.h"
#include "router.h"
#include "state.h"

static const char *get_path_from_params(const struct peer *p, const cJSON *params, cJSON **err)
{
	const cJSON *path = cJSON_GetObjectItem(params, "path");
	if (unlikely(path == NULL)) {
		cJSON *error =
			create_invalid_params_error(p, "reason", "no path given");
		*err = error;
		return NULL;
	}
	if (unlikely(path->type != cJSON_String)) {
		cJSON *error = create_invalid_params_error(
			p, "reason", "path is not a string");
		*err = error;
		return NULL;
	}
	*err = NULL;
	return path->valuestring;
}

static int get_fetch_only_from_params(const struct peer *p, const cJSON *params, cJSON **err)
{
	const cJSON *fetch_only = cJSON_GetObjectItem(params, "fetchOnly");
	if (fetch_only == NULL || (fetch_only->type == cJSON_False)) {
		*err = NULL;
		return 0;
	}
	if (fetch_only->type == cJSON_True) {
		*err = NULL;
		return FETCH_ONLY_FLAG;
	}
	cJSON *error = create_invalid_params_error(
		p, "reason", "fetchOnly is not a bool");
	*err = error;
	return 0;
}

static int possibly_send_response(const cJSON *json_rpc, cJSON *error, const struct peer *p)
{
	int ret = 0;
	if (error == (cJSON *)ROUTED_MESSAGE) {
		return ret;
	}

	cJSON *id = cJSON_GetObjectItem(json_rpc, "id");
	if (likely(id != NULL)) {
		cJSON *root;
		char *rendered;
		if (unlikely(error != NULL)) {
			root = create_error_response(p, id, error);
		} else {
			root = create_boolean_success_response(p, id, TRUE);
		}

		if (unlikely(root == NULL)) {
			if (error != NULL) {
				cJSON_Delete(error);
			}
			return -1;
		}
		rendered = cJSON_PrintUnformatted(root);
		if (unlikely(rendered == NULL)) {
			log_peer_err(p, "Could not render JSON into a string!\n");
			ret = -1;
			goto render_error;
		}
		ret = p->send_message(p, rendered, strlen(rendered));
		cJSON_free(rendered);
	render_error:
		cJSON_Delete(root);
	} else {
		if (error != NULL) {
			cJSON_Delete(error);
		}
	}
	return ret;
}

static int process_change(const cJSON *json_rpc, const struct peer *p)
{
	const cJSON *params = cJSON_GetObjectItem(json_rpc, "params");
	if (unlikely(params == NULL)) {
		cJSON *error =
			create_invalid_params_error(p, "reason", "no params found");
		return possibly_send_response(json_rpc, error, p);
	}

	cJSON *error;
	const char *path = get_path_from_params(p, params, &error);
	if (unlikely(path == NULL)) {
		return possibly_send_response(json_rpc, error, p);
	}

	const cJSON *value = cJSON_GetObjectItem(params, "value");
	if (unlikely(value == NULL)) {
		error = create_invalid_params_error(p, "reason", "no value given");
		return possibly_send_response(json_rpc, error, p);
	}
	error = change_state(p, path, value);
	return possibly_send_response(json_rpc, error, p);
}

static int process_set(const cJSON *json_rpc, const struct peer *p)
{
	const cJSON *params = cJSON_GetObjectItem(json_rpc, "params");
	if (unlikely(params == NULL)) {
		cJSON *error =
			create_invalid_params_error(p, "reason", "no params found");
		return possibly_send_response(json_rpc, error, p);
	}

	cJSON *error;
	const char *path = get_path_from_params(p, params, &error);
	if (unlikely(path == NULL)) {
		return possibly_send_response(json_rpc, error, p);
	}

	const cJSON *value = cJSON_GetObjectItem(params, "value");
	if (unlikely(value == NULL)) {
		error = create_invalid_params_error(p, "reason", "no value given");
		return possibly_send_response(json_rpc, error, p);
	}
	error = set_or_call(p, path, value, json_rpc, STATE);
	return possibly_send_response(json_rpc, error, p);
}

static int process_call(const cJSON *json_rpc, const struct peer *p)
{
	const cJSON *params = cJSON_GetObjectItem(json_rpc, "params");
	if (unlikely(params == NULL)) {
		cJSON *error =
			create_invalid_params_error(p, "reason", "no params found");
		return possibly_send_response(json_rpc, error, p);
	}

	cJSON *error;
	const char *path = get_path_from_params(p, params, &error);
	if (unlikely(path == NULL)) {
		return possibly_send_response(json_rpc, error, p);
	}
	const cJSON *args = cJSON_GetObjectItem(params, "args");
	error = set_or_call(p, path, args, json_rpc, METHOD);
	return possibly_send_response(json_rpc, error, p);
}

static int process_add(const cJSON *json_rpc, struct peer *p)
{
	if (CONFIG_ALLOW_ADD_ONLY_FROM_LOCALHOST) {
		if (!p->is_local_connection) {
			cJSON *error =
				create_invalid_request_error(p, "reason", "add only allowed from localhost");
			return possibly_send_response(json_rpc, error, p);
		}
	}

	const cJSON *params = cJSON_GetObjectItem(json_rpc, "params");
	if (unlikely(params == NULL)) {
		cJSON *error =
			create_invalid_params_error(p, "reason", "no params found");
		return possibly_send_response(json_rpc, error, p);
	}

	cJSON *error = NULL;
	const char *path = get_path_from_params(p, params, &error);
	if (unlikely(path == NULL)) {
		return possibly_send_response(json_rpc, error, p);
	}

	int flags = get_fetch_only_from_params(p, params, &error);
	if (unlikely(error != NULL)) {
		return possibly_send_response(json_rpc, error, p);
	}

	const cJSON *value = cJSON_GetObjectItem(params, "value");
	error = add_state_or_method_to_peer(p, path, value, flags, CONFIG_ROUTED_MESSAGES_TIMEOUT);

	return possibly_send_response(json_rpc, error, p);
}

static int process_remove(const cJSON *json_rpc, const struct peer *p)
{
	const cJSON *params = cJSON_GetObjectItem(json_rpc, "params");
	if (unlikely(params == NULL)) {
		cJSON *error =
			create_invalid_params_error(p, "reason", "no params found");
		return possibly_send_response(json_rpc, error, p);
	}

	cJSON *error;
	const char *path = get_path_from_params(p, params, &error);
	if (unlikely(path == NULL)) {
		return possibly_send_response(json_rpc, error, p);
	}

	int ret = remove_state_or_method_from_peer(p, path);
	if (ret == 0) {
		return possibly_send_response(json_rpc, NULL, p);
	}
	if (ret != 0) {
		error = create_invalid_params_error(p, "not exists", path);
	}
	return possibly_send_response(json_rpc, error, p);
}

static int process_fetch(const cJSON *json_rpc, struct peer *p)
{
	const cJSON *params = cJSON_GetObjectItem(json_rpc, "params");
	if (unlikely(params == NULL)) {
		cJSON *error =
			create_invalid_params_error(p, "reason", "no params found");
		return possibly_send_response(json_rpc, error, p);
	}

	struct fetch *f = NULL;
	cJSON *error = add_fetch_to_peer(p, params, &f);
	if (likely(error == NULL)) {
		error = add_fetch_to_states(f);
	}
	return possibly_send_response(json_rpc, error, p);
}

static int process_unfetch(const cJSON *json_rpc, const struct peer *p)
{
	const cJSON *params = cJSON_GetObjectItem(json_rpc, "params");
	if (unlikely(params == NULL)) {
		cJSON *error =
			create_invalid_params_error(p, "reason", "no params found");
		return possibly_send_response(json_rpc, error, p);
	}

	cJSON *error = remove_fetch_from_peer(p, params);
	return possibly_send_response(json_rpc, error, p);
}

static int process_config(const cJSON *json_rpc, struct peer *p)
{
	const cJSON *params = cJSON_GetObjectItem(json_rpc, "params");
	if (unlikely(params == NULL)) {
		cJSON *error =
			create_invalid_params_error(p, "reason", "no params found");
		return possibly_send_response(json_rpc, error, p);
	}

	cJSON *error = config_peer(p, params);
	return possibly_send_response(json_rpc, error, p);
}

static int handle_method(const cJSON *json_rpc, const char *method_name,
	struct peer *p)
{
	if (strcmp(method_name, "change") == 0) {
		return process_change(json_rpc, p);
	} else if (strcmp(method_name, "set") == 0) {
		return process_set(json_rpc, p);
	} else if (strcmp(method_name, "call") == 0) {
		return process_call(json_rpc, p);
	} else if (strcmp(method_name, "add") == 0) {
		return process_add(json_rpc, p);
	} else if (strcmp(method_name, "remove") == 0) {
		return process_remove(json_rpc, p);
	} else if (strcmp(method_name, "fetch") == 0) {
		return process_fetch(json_rpc, p);
	} else if (strcmp(method_name, "unfetch") == 0) {
		return process_unfetch(json_rpc, p);
	} else if (strcmp(method_name, "config") == 0) {
		return process_config(json_rpc, p);
	} else if (strcmp(method_name, "info") == 0) {
		return handle_info(json_rpc, p);
	} else {
		cJSON *error = create_method_not_found_error(p, "reason", method_name);
		return possibly_send_response(json_rpc, error, p);
	}
}

static int parse_json_rpc(const cJSON *json_rpc, struct peer *p)
{
	int ret;
	const cJSON *method = cJSON_GetObjectItem(json_rpc, "method");
	if (method != NULL) {
		if (unlikely(method->type != cJSON_String)) {
			cJSON *error = create_invalid_request_error(
				p, "reason", "method value is not a string");
			return possibly_send_response(json_rpc, error, p);
		}
		const char *method_name = method->valuestring;
		ret = handle_method(json_rpc, method_name, p);
		return ret;
	}

	const cJSON *result = cJSON_GetObjectItem(json_rpc, "result");
	if (result != NULL) {
		ret = handle_routing_response(json_rpc, result, "result", p);
		return ret;
	}

	cJSON *error = cJSON_GetObjectItem(json_rpc, "error");
	if (error != NULL) {
		ret = handle_routing_response(json_rpc, error, "error", p);
		return ret;
	}


	error = create_invalid_request_error(p, "reason", "neither request nor response");
	ret = possibly_send_response(json_rpc, error, p);
	return ret;
}

static int parse_json_array(cJSON *root, struct peer *p)
{
	unsigned int array_size = cJSON_GetArraySize(root);
	for (unsigned int i = 0; i < array_size; ++i) {
		cJSON *sub_item = cJSON_GetArrayItem(root, i);
		if (likely(sub_item->type == cJSON_Object)) {
			int ret = parse_json_rpc(sub_item, p);
			if (unlikely(ret == -1)) {
				return -1;
			}
		} else {
			log_peer_err(p, "JSON is not an object!\n");
			return -1;
		}
	}
	return 0;
}

int parse_message(const char *msg, uint32_t length, struct peer *p)
{
	int ret = 0;

	const char *end_parse;
	cJSON *root = cJSON_ParseWithOpts(msg, &end_parse, 0);
	if (unlikely(root == NULL)) {
		log_peer_err(p, "Could not parse JSON!\n");
		return -1;
	}

	if (CONFIG_CHECK_JSON_LENGTH) {
		ptrdiff_t parsed_length = end_parse - msg;
		if (unlikely(parsed_length != (ptrdiff_t)length)) {
			log_peer_err(p, "length of parsed JSON (%td) does not "
				"match message length (%u)!\n",
				parsed_length, length);
			ret = -1;
			goto out;
		}
	}

	switch (root->type) {
	case cJSON_Array:
		ret = parse_json_array(root, p);
		break;

	case cJSON_Object:
		ret = parse_json_rpc(root, p);
		break;

	default:
		log_peer_err(p, "JSON is neither array nor object!\n");
		ret = -1;
		break;
	}

out:
	cJSON_Delete(root);
	return ret;
}

void init_parser(void)
{
	cJSON_Hooks hooks = {
		.malloc_fn = cjet_malloc,
		.free_fn = cjet_free
	};
	cJSON_InitHooks(&hooks);
}
