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

#ifndef CJET_HANDLE_FETCH_H
#define CJET_HANDLE_FETCH_H

#include "element.h"
#include "list.h"
#include "peer.h"
#include "json/cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

struct path_matcher;
struct element;

typedef int (*match_func)(const struct path_matcher *pm, const char *state_path);

struct path_matcher {
	match_func match_function;
	unsigned int number_of_path_elements;
	char *path_elements[1];
};

struct fetch {
	cJSON *fetch_id;
	const struct peer *peer;
	unsigned int number_of_matchers;
	struct list_head next_fetch;
	struct path_matcher *matcher[1];
};

int add_fetch_to_peer(struct peer *p, const cJSON *request, struct fetch **fetch_return, cJSON **response);
cJSON *get_elements(const cJSON *request, const struct peer *request_peer);
cJSON *remove_fetch_from_peer(const struct peer *p, const cJSON *request);
void remove_all_fetchers_from_peer(struct peer *p);
cJSON *add_fetch_to_states(const struct peer *request_peer, const cJSON *request, const struct fetch *f);
int find_fetchers_for_element(struct element *e);

int notify_fetchers(const struct element *e, const char *event_name);

#ifdef __cplusplus
}
#endif

#endif
