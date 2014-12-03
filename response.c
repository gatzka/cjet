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

#include <stdio.h>

#include "compiler.h"
#include "json/cJSON.h"
#include "response.h"

static cJSON *add_sub_to_object(cJSON *root, cJSON *sub, const char *name)
{
	if (unlikely(sub == NULL)) {
		fprintf(stderr, "Could not allocate memory for object!\n");
		cJSON_Delete(root);
		root = NULL;
	} else {
		cJSON_AddItemToObject(root, name, sub);
	}
	return root;
}

static cJSON *create_common_response(const cJSON *id)
{
	cJSON *root = cJSON_CreateObject();
	if (unlikely(root == NULL)) {
		return NULL;
	}

	switch (id->type) {

	case cJSON_String:
		root = add_sub_to_object(root,
			cJSON_CreateString(id->valuestring), "id");
		break;

	case cJSON_Number:
		root = add_sub_to_object(root,
			cJSON_CreateNumber(id->valueint), "id");
		break;

	default:
		fprintf(stderr, "Unsupported method id type!");
		cJSON_Delete(root);
		root = NULL;
		break;
	}
	return root;
}

static cJSON *create_error_object(const char *message, int code,
	const char *tag, const char *reason)
{
	cJSON *error = cJSON_CreateObject();
	if (unlikely(error == NULL)) {
		goto err;
	}
	error = add_sub_to_object(error, cJSON_CreateString(message), "message");
	if (unlikely(error == NULL)) {
		goto err;
	}
	error = add_sub_to_object(error, cJSON_CreateNumber(code), "code");
	if (unlikely(error == NULL)) {
		goto err;
	}
	if ((tag != NULL) && (reason != NULL)) {
		cJSON *data = cJSON_CreateObject();
		error = add_sub_to_object(error, cJSON_CreateObject(), "data");
		if (likely(error != NULL)) {
			cJSON_AddItemToObject(error, "data", data);
			error = add_sub_to_object(error, cJSON_CreateString(reason), tag);
			if (unlikely(error == NULL)) {
				goto err;
			}
		}
	}
	return error;

err:
	fprintf(stderr, "Could not create error JSON object!\n");
	return NULL;
}

cJSON *create_invalid_request_error(const char *tag, const char *reason)
{
	return create_error_object("Invalid Request", -32600, tag, reason);
}

cJSON *create_method_not_found_error(const char *tag, const char *reason)
{
	return create_error_object("Method not found", -32601, tag, reason);
}

cJSON *create_invalid_params_error(const char *tag, const char *reason)
{
	return create_error_object("Invalid params", -32602, tag, reason);
}

cJSON *create_internal_error(const char *tag, const char *reason)
{
	return create_error_object("Internal error", -32603, tag, reason);
}

cJSON *create_error_response(const cJSON *id, cJSON *error)
{
	cJSON *root = create_common_response(id);
	if (unlikely(root == NULL)) {
		return NULL;
	}
	cJSON_AddItemToObject(root, "error", error);
	return root;
}

cJSON *create_boolean_success_response(const cJSON *id, int true_false)
{
	cJSON *root = create_common_response(id);
	if (unlikely(root == NULL)) {
		return NULL;
	}
	cJSON *boolean;
	if (true_false == 0) {
		boolean = cJSON_CreateFalse();
	} else {
		boolean = cJSON_CreateTrue();
	}
	root = add_sub_to_object(root, boolean, "result");
	return root;
}

cJSON *create_result_response(const cJSON *id, cJSON *result)
{
	cJSON *root = create_common_response(id);
	if (unlikely(root == NULL)) {
		return NULL;
	}
	cJSON_AddItemToObject(root, "result", result);
	return root;
}
