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

#include "alloc.h"
#include "compiler.h"
#include "json/cJSON.h"
#include "uuid.h"

static unsigned int uuid = 0;

size_t calculate_size_for_routed_request_id(const void *address, const cJSON *origin_request_id)
{
	if (origin_request_id != NULL) {
		return snprintf(NULL, 0, "%s_%x_%p", origin_request_id->valuestring, uuid, address);
	} else {
		return snprintf(NULL, 0, "%x_%p", uuid, address);
	}
}

void fill_routed_request_id(char *buf, size_t buf_size, const void *address, const cJSON *origin_request_id)
{

	if (origin_request_id != NULL) {
		snprintf(buf, buf_size, "%s_%x_%p", origin_request_id->valuestring, uuid, address);
	} else {
		snprintf(buf, buf_size, "%x_%p", uuid, address);
	}
}

char *alloc_routed_request_uuid(void *address, const cJSON *origin_request_id)
{
	uuid++;
	if (origin_request_id != NULL) {
		if (origin_request_id->type == cJSON_String) {
			size_t needed = snprintf(NULL, 0, "%s_%x_%p", origin_request_id->valuestring, uuid, address);
			char *buf = cjet_malloc(needed);
			if (likely(buf != NULL)) {
				snprintf(buf, needed, "%s_%x_%p", origin_request_id->valuestring, uuid, address);
			}
			return buf;
		} else {
			size_t needed = snprintf(NULL, 0, "%x_%x_%p", origin_request_id->valueint, uuid, address);
			char *buf = cjet_malloc(needed);
			if (likely(buf != NULL)) {
				snprintf(buf, needed, "%x_%x_%p", origin_request_id->valueint, uuid, address);
			}
			return buf;
		}
	} else {
		size_t needed = snprintf(NULL, 0, "%x_%p", uuid, address);
		char *buf = cjet_malloc(needed);
		if (likely(buf != NULL)) {
			snprintf(buf, needed, "%x_%p", uuid, address);
		}
		return buf;
	}
}
