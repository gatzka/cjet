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
#include "response.h"

cJSON *handle_authentication(struct peer *p, const cJSON *request, const char *user, char *passwd)
{
	if (unlikely(!list_empty(&p->fetch_list))) {
		cJSON *error = create_error_object(p, INVALID_PARAMS, "fetched before authenticate", user);
		return create_error_response_from_request(p, request, error);
	}

	const cJSON *auth = credentials_ok(user, passwd);
	if (auth == NULL) {
		cJSON *error = create_error_object(p, INVALID_PARAMS, "invalid credentials", user);
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
