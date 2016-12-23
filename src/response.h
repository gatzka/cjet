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

#ifndef CJET_RESPONSE_H
#define CJET_RESPONSE_H

#include "json/cJSON.h"
#include "peer.h"

#ifdef __cplusplus
extern "C" {
#endif

#define INVALID_REQUEST -32600
#define METHOD_NOT_FOUND -32601
#define INVALID_PARAMS -32602
#define INTERNAL_ERROR -32603

cJSON *create_success_response_from_request(const struct peer *p, const cJSON *request);
cJSON *create_result_response(const struct peer *p, const cJSON *id, cJSON *result, const char *result_type);
cJSON *create_result_response_from_request(const struct peer *p, const cJSON *request, cJSON *result, const char *result_type);
cJSON *create_error_response(const struct peer *p, const cJSON *id, int code, const char *tag, const char *reason);
cJSON *create_error_response_from_request(const struct peer *p, const cJSON *request, int code, const char *tag, const char *reason);

#ifdef __cplusplus
}
#endif

#endif
