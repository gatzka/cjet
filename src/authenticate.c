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
#include "jet_string.h"
#include "list.h"
#include "log.h"
#include "peer.h"
#include "request.h"
#include "response.h"
#include "json/cJSON.h"

cJSON *handle_authentication(struct peer *p, const cJSON *request)
{
	cJSON *response = NULL;
	const cJSON *params = get_params(p, request, &response);
	if (unlikely(params == NULL)) {
		return response;
	}

	const cJSON *user = cJSON_GetObjectItem(params, "user");
	if (unlikely(user == NULL)) {
		return create_error_response_from_request(p, request, INVALID_PARAMS, "reason", "no user given");
	}

	if (unlikely(user->type != cJSON_String)) {
		return create_error_response_from_request(p, request, INVALID_PARAMS, "reason", "user is not a string");
	}

	const cJSON *passwd = cJSON_GetObjectItem(params, "password");
	if (unlikely(passwd == NULL)) {
		return create_error_response_from_request(p, request, INVALID_PARAMS, "reason", "no password given");
	}

	if (unlikely(passwd->type != cJSON_String)) {
		return create_error_response_from_request(p, request, INVALID_PARAMS, "reason", "password is not a string");
	}

	if (unlikely(!list_empty(&p->fetch_list))) {
		return create_error_response_from_request(p, request, INVALID_PARAMS, "fetched before authenticate", user->valuestring);
	}

	const cJSON *auth = credentials_ok(user->valuestring, passwd->valuestring);
	if (auth == NULL) {
		return create_error_response_from_request(p, request, INVALID_PARAMS, "invalid credentials", user->valuestring);
	}

	const cJSON *fetch_groups = cJSON_GetObjectItem(auth, "fetchGroups");
	p->fetch_groups = get_groups(fetch_groups);
	const cJSON *set_groups = cJSON_GetObjectItem(auth, "setGroups");
	p->set_groups = get_groups(set_groups);
	const cJSON *call_groups = cJSON_GetObjectItem(auth, "callGroups");
	p->call_groups = get_groups(call_groups);

	p->user_name = duplicate_string(user->valuestring);
	if (p->user_name == NULL) {
		return create_error_response_from_request(p, request, INTERNAL_ERROR, "reason", "not enough memory to allocate user name");
	}

	return create_success_response_from_request(p, request);
}

cJSON *handle_change_password(const struct peer *p, const cJSON *request)
{
	cJSON *response = NULL;
	const cJSON *params = get_params(p, request, &response);
	if (unlikely(params == NULL)) {
		return response;
	}

	const cJSON *user = cJSON_GetObjectItem(params, "user");
	if (unlikely(user == NULL)) {
		return create_error_response_from_request(p, request, INVALID_PARAMS, "reason", "no user given");
	}

	if (unlikely(user->type != cJSON_String)) {
		return create_error_response_from_request(p, request, INVALID_PARAMS, "reason", "user is not a string");
	}

	const cJSON *passwd = cJSON_GetObjectItem(params, "password");
	if (unlikely(passwd == NULL)) {
		return create_error_response_from_request(p, request, INVALID_PARAMS, "reason", "no password given");
	}

	if (unlikely(passwd->type != cJSON_String)) {
		return create_error_response_from_request(p, request, INVALID_PARAMS, "reason", "password is not a string");
	}

	return change_password(p, request, user->valuestring, passwd->valuestring);
}
