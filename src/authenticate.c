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
#include "json/cJSON.h"
#include "list.h"
#include "peer.h"
#include "response.h"

cJSON *handle_authentication(struct peer *p, const char *user, char *passwd)
{
	if (!list_empty(&p->fetch_list)) {
		cJSON *error = create_invalid_params_error(p, "fetched before authenticate", user);
		return error;
	}

	const cJSON *auth = credentials_ok(user, passwd);
	if (auth == NULL) {
		cJSON *error = create_invalid_params_error(p, "invalid credentials", user);
		return error;
	}

	p->auth = cJSON_Duplicate(auth, 1);
	if (p->auth == NULL) {
		cJSON *error = create_invalid_params_error(p, "Could not allocate memory for auth object", user);
		return error;
	}

	return NULL;
}
