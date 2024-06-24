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
#include "config.h"
#include "peer.h"
#include "request.h"
#include "response.h"
#include "cJSON.h"

cJSON *config_peer(struct peer *p, const cJSON *request)
{
	cJSON *response = NULL;
	const cJSON *params = get_params(p, request, &response);
	if (unlikely(params == NULL)) {
		return response;
	}

	cJSON *name = cJSON_GetObjectItem(params, "name");
	if (name != NULL) {
		if (unlikely(name->type != cJSON_String)) {
			return create_error_response_from_request(p, request, INVALID_PARAMS, "reason", "name is not a string");
		}

		set_peer_name(p, name->valuestring);
	}

	return create_success_response_from_request(p, request);
}
