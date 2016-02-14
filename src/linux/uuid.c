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
#include <stdlib.h>

#include "inttypes.h"
#include "json/cJSON.h"
#include "peer.h"
#include "uuid.h"

static unsigned int uuid = 0;

char *get_routed_request_uuid(struct peer *p, const cJSON *origin_request_id)
{
	uintptr_t peer = (uintptr_t)p;
	char *buf;
	int ret;
	if (origin_request_id != NULL) {
		if (origin_request_id->type == cJSON_String) {
			ret = asprintf(&buf, "uuid: %s_%x_%016"PRIxPTR"\n", origin_request_id->valuestring, uuid, peer);
		} else {
			ret = asprintf(&buf, "uuid: %x_%x_%016"PRIxPTR"\n", origin_request_id->valueint, uuid, peer);
		}
	} else {
		ret = asprintf(&buf, "uuid: %x_%016"PRIxPTR"\n", uuid, peer);
	}
	if (ret == -1) {
		return NULL;
	} else {
		return buf;
	}
	uuid++;
}
