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

static cJSON *create_common_response(const cJSON *id)
{
	cJSON *root = cJSON_CreateObject();
	if (unlikely(root == NULL)) {
		return NULL;
	}

	switch (id->type) {

	case cJSON_String:
		cJSON_AddStringToObject(root, "id", id->valuestring);
		break;

	case cJSON_Number:
		cJSON_AddNumberToObject(root, "id", id->valueint);
		break;

	default:
		fprintf(stderr, "Unsupported method id type!");
		goto unsupported_type;

	}
	return root;

unsupported_type:
	cJSON_Delete(root);
	return NULL;
}

static cJSON *create_error_object(const char *message, int code, const char *tag, const char *reason)
{
	cJSON *error = cJSON_CreateObject();
	if (unlikely(error == NULL)) {
		fprintf(stderr, "Could not create error JSON object!\n");
		return NULL;
	}
	cJSON_AddStringToObject(error, "message", message);
	cJSON_AddNumberToObject(error, "code", code);
	if ((tag != NULL) && (reason != NULL)) {
		cJSON *data = cJSON_CreateObject();
		if (likely(data != NULL)) {
			cJSON_AddStringToObject(data, tag, reason);
			cJSON_AddItemToObject(error, "data", data);
		}
	}
	return error;
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
	return create_error_object("Invalid params", -32603, tag, reason);
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
	if (true_false == 0) {
		cJSON_AddFalseToObject(root, "result");
	} else {
		cJSON_AddTrueToObject(root, "result");
	}
	return root;
}
