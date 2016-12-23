/*
 *The MIT License (MIT)
 *
 * Copyright (c) <2016> <Stephan Gatzka>
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

#include "authenticate.h"
#include "compiler.h"
#include "groups.h"
#include "json/cJSON.h"
#include "list.h"
#include "log.h"
#include "peer.h"
#include "request.h"
#include "response.h"

cJSON *handle_authentication(struct peer *p, const cJSON *request)
{
	cJSON *response;
	const cJSON *params = get_params(p, request, &response);
	if (unlikely(params == NULL)) {
		return response;
	}

	const cJSON *user = cJSON_GetObjectItem(params, "user");
	if (unlikely(user == NULL)) {
		cJSON *error = create_error_object(p, INVALID_PARAMS, "reason", "no user given");
		return create_error_response_from_request(p, request, error);
	}

	if (unlikely(user->type != cJSON_String)) {
		cJSON *error = create_error_object(p, INVALID_PARAMS, "reason", "user is not a string");
		return create_error_response_from_request(p, request, error);
	}

	const cJSON *passwd = cJSON_GetObjectItem(params, "password");
	if (unlikely(passwd == NULL)) {
		cJSON *error = create_error_object(p, INVALID_PARAMS, "reason", "no password given");
		return create_error_response_from_request(p, request, error);
	}

	if (unlikely(passwd->type != cJSON_String)) {
		cJSON *error = create_error_object(p, INVALID_PARAMS, "reason", "password is not a string");
		return create_error_response_from_request(p, request, error);
	}

	if (unlikely(!list_empty(&p->fetch_list))) {
		cJSON *error = create_error_object(p, INVALID_PARAMS, "fetched before authenticate", user->valuestring);
		return create_error_response_from_request(p, request, error);
	}

	const cJSON *auth = credentials_ok(user->valuestring, passwd->valuestring);
	if (auth == NULL) {
		cJSON *error = create_error_object(p, INVALID_PARAMS, "invalid credentials", user->valuestring);
		return create_error_response_from_request(p, request, error);
	}

	const cJSON *fetch_groups = cJSON_GetObjectItem(auth, "fetchGroups");
	p->fetch_groups = get_groups(fetch_groups);
	const cJSON *set_groups = cJSON_GetObjectItem(auth, "setGroups");
	p->set_groups = get_groups(set_groups);
	const cJSON *call_groups = cJSON_GetObjectItem(auth, "callGroups");
	p->call_groups = get_groups(call_groups);

	return create_success_response_from_request(p, request);
}
