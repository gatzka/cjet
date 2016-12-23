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

#include "compiler.h"
#include "json/cJSON.h"
#include "peer.h"
#include "response.h"

static cJSON *add_subobject_to_object(const struct peer *p, cJSON *root, cJSON *value, const char *key)
{
	if (unlikely(value == NULL)) {
		log_peer_err(p, "Could not allocate memory for %s object!\n", key);
		cJSON_Delete(root);
		root = NULL;
	} else {
		cJSON_AddItemToObject(root, key, value);
	}
	return root;
}

static cJSON *create_common_response(const struct peer *p, const cJSON *id)
{
	cJSON *root = cJSON_CreateObject();
	if (unlikely(root == NULL)) {
		return NULL;
	}

	switch (id->type) {

	case cJSON_String:
		root = add_subobject_to_object(p, root,
			cJSON_CreateString(id->valuestring), "id");
		break;

	case cJSON_Number:
		root = add_subobject_to_object(p, root,
			cJSON_CreateNumber(id->valueint), "id");
		break;

	default:
		log_peer_err(p, "Unsupported method id type!\n");
		cJSON_Delete(root);
		root = NULL;
		break;
	}
	return root;
}

cJSON *create_error_object(const struct peer *p, int code, const char *tag, const char *reason)
{
	cJSON *error = cJSON_CreateObject();
	if (unlikely(error == NULL)) {
		goto err;
	}

	cJSON *error_message;
	switch (code) {
	case INVALID_REQUEST:
		error_message = cJSON_CreateString("Invalid Request");
		break;

	case METHOD_NOT_FOUND:
		error_message = cJSON_CreateString("Method not found");
		break;

	case INVALID_PARAMS:
		error_message = cJSON_CreateString("Invalid params");
		break;

	case INTERNAL_ERROR:
		error_message = cJSON_CreateString("Internal error");
		break;

	default:
		error_message = cJSON_CreateString("Unknown error");
		break;
	}

	error = add_subobject_to_object(p, error, error_message, "message");
	if (unlikely(error == NULL)) {
		goto err;
	}

	error = add_subobject_to_object(p, error, cJSON_CreateNumber(code), "code");
	if (unlikely(error == NULL)) {
		goto err;
	}

	if ((tag != NULL) && (reason != NULL)) {
		cJSON *data = cJSON_CreateObject();
		if (likely(data != NULL)) {
			cJSON_AddItemToObject(error, "data", data);
			if (unlikely(add_subobject_to_object(p, data, cJSON_CreateString(reason), tag) == NULL)) {
				goto err;
			}
		}
	}

	return error;

err:
	log_peer_err(p, "Could not create error JSON object!\n");
	return NULL;
}

cJSON *create_invalid_params_error(const struct peer *p, const char *tag, const char *reason)
{
	return create_error_object(p, -32602, tag, reason);
}

cJSON *create_internal_error(const struct peer *p, const char *tag, const char *reason)
{
	return create_error_object(p, -32603, tag, reason);
}

cJSON *create_error_response(const struct peer *p, const cJSON *id, cJSON *error)
{
	cJSON *root = create_common_response(p, id);
	if (unlikely(root == NULL)) {
		return NULL;
	}
	cJSON_AddItemToObject(root, "error", error);
	return root;
}

cJSON *create_error_response_from_request(const struct peer *p, const cJSON *request, cJSON *error)
{
	const cJSON *id = cJSON_GetObjectItem(request, "id");
	if (id != NULL) {
		cJSON *response = create_error_response(p, id, error);
		if (likely(response != NULL)) {
			return response;
		}
	}

	cJSON_Delete(error);
	return NULL;
}

cJSON *create_success_response_from_request(const struct peer *p, const cJSON *request)
{
	const cJSON *id = cJSON_GetObjectItem(request, "id");
	if (id != NULL) {
		cJSON *root = create_common_response(p, id);
		if (unlikely(root == NULL)) {
			return NULL;
		}
// TODO
		root = add_subobject_to_object(p, root, cJSON_CreateTrue(), "result");
		return root;
	}

	return NULL;
}

cJSON *create_result_response(const struct peer *p, const cJSON *id, cJSON *result, const char *result_type)
{
	cJSON *root = create_common_response(p, id);
	if (unlikely(root == NULL)) {
		return NULL;
	}
	cJSON_AddItemToObject(root, result_type, result);
	return root;
}

cJSON *create_result_response_from_request(const struct peer *p, const cJSON *request, cJSON *result, const char *result_type)
{
	const cJSON *id = cJSON_GetObjectItem(request, "id");
	if (id != NULL) {
		cJSON *response = create_common_response(p, id);
		if (unlikely(response == NULL)) {
			return NULL;
		}

		cJSON_AddItemToObject(response, result_type, result);
		return response;
	} else {
		cJSON_Delete(result);
		return NULL;
	}
}
