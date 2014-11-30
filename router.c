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
#include "router.h"

cJSON *create_routed_message(const char *path, cJSON *value, int id)
{
	cJSON *message = cJSON_CreateObject();
	if (unlikely(message == NULL)) {
		return NULL;
	}

	cJSON *json_id = cJSON_CreateNumber(id);
	if (unlikely(json_id == NULL)) {
		goto error;
	}
	cJSON_AddItemToObject(message, "id", json_id);

	cJSON *method = cJSON_CreateString(path);
	if (unlikely(method == NULL)) {
		goto error;
	}
	cJSON_AddItemToObject(message, "method", method);

	cJSON *params = cJSON_CreateObject();
	if (unlikely(params == NULL)) {
		goto error;
	}
	cJSON_AddItemToObject(message, "params", params);

	cJSON *value_copy = cJSON_Duplicate(value, 1);
	if (unlikely(value_copy == NULL)) {
		goto error;
	}
	cJSON_AddItemToObject(params, "value", value_copy);
	return message;

error:
	fprintf(stderr, "Could not allocate memory for %s object!\n", "routed");
	cJSON_Delete(message);
	return NULL;
}

