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

#ifndef CJET_AUTHENTICATE_H
#define CJET_AUTHENTICATE_H

#include <stdbool.h>

#include "peer.h"
#include "cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

cJSON *handle_authentication(struct peer *p, const cJSON *request);
cJSON *handle_change_password(const struct peer *p, const cJSON *request);

int load_passwd_data(const char *passwd_file);
void free_passwd_data(void);
const cJSON *credentials_ok(const char *user_name, char *passwd);
cJSON *change_password(const struct peer *p, const cJSON *request, const char *user_name, char *passwd);

#ifdef __cplusplus
}
#endif

#endif
