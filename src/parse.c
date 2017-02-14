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

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "alloc.h"
#include "authenticate.h"
#include "compiler.h"
#include "config.h"
#include "element.h"
#include "fetch.h"
#include "generated/cjet_config.h"
#include "info.h"
#include "linux/linux_io.h"
#include "parse.h"
#include "peer.h"
#include "response.h"
#include "router.h"
#include "json/cJSON.h"

static int send_response(cJSON *response, const struct peer *p)
{
	if (response == NULL) {
		return 0;
	}

	int ret;
	char *rendered = cJSON_PrintUnformatted(response);
	if (unlikely(rendered == NULL)) {
		log_peer_err(p, "Could not render JSON into a string!\n");
		ret = -1;
		goto render_error;
	}

	ret = p->send_message(p, rendered, strlen(rendered));
	cJSON_free(rendered);

render_error:
	cJSON_Delete(response);
	return ret;
}

static cJSON *process_fetch(const cJSON *json_rpc, struct peer *p)
{
	struct fetch *f = NULL;
	cJSON *response;
	if (unlikely(add_fetch_to_peer(p, json_rpc, &f, &response) < 0)) {
		return response;
	}

	return add_fetch_to_states(p, json_rpc, f);
}

static cJSON *handle_method(const cJSON *request, const char *method_name,
                            struct peer *p)
{
	if (strcmp(method_name, "change") == 0) {
		return change_state(p, request);
	} else if (strcmp(method_name, "set") == 0) {
		return set_or_call(p, request, STATE);
	} else if (strcmp(method_name, "call") == 0) {
		return set_or_call(p, request, METHOD);
	} else if (strcmp(method_name, "add") == 0) {
		return add_element_to_peer(p, request);
	} else if (strcmp(method_name, "remove") == 0) {
		return remove_element_from_peer(p, request);
	} else if (strcmp(method_name, "fetch") == 0) {
		return process_fetch(request, p);
	} else if (strcmp(method_name, "unfetch") == 0) {
		return remove_fetch_from_peer(p, request);
	} else if (strcmp(method_name, "get") == 0) {
		return get_elements(request, p);
	} else if (strcmp(method_name, "config") == 0) {
		return config_peer(p, request);
	} else if (strcmp(method_name, "info") == 0) {
		return handle_info(request, p);
	} else if (strcmp(method_name, "authenticate") == 0) {
		return handle_authentication(p, request);
	} else if (strcmp(method_name, "passwd") == 0) {
		return handle_change_password(p, request);
	} else {
		return create_error_response_from_request(p, request, METHOD_NOT_FOUND, "reason", method_name);
	}
}

static int parse_json_rpc(const cJSON *request, struct peer *p)
{
	cJSON *response;

	const cJSON *method = cJSON_GetObjectItem(request, "method");
	if (method != NULL) {
		if (unlikely(method->type != cJSON_String)) {
			response = create_error_response_from_request(p, request, INVALID_REQUEST, "reason", "method is not a string");
		} else {
			const char *method_name = method->valuestring;
			response = handle_method(request, method_name, p);
		}
	} else {
		int ret;
		const cJSON *result = cJSON_GetObjectItem(request, "result");
		if (result != NULL) {
			ret = handle_routing_response(request, result, "result", p);
			return ret;
		}

		cJSON *error = cJSON_GetObjectItem(request, "error");
		if (error != NULL) {
			ret = handle_routing_response(request, error, "error", p);
			return ret;
		}

		response = create_error_response_from_request(p, request, INVALID_REQUEST, "reason", "neither request nor response");
	}

	return send_response(response, p);
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
	    .free_fn = cjet_free};
	cJSON_InitHooks(&hooks);
}
