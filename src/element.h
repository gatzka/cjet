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

#ifndef CJET_HANDLE_STATE_H
#define CJET_HANDLE_STATE_H

#include <stdbool.h>

#include "fetch.h"
#include "groups.h"
#include "json/cJSON.h"
#include "list.h"
#include "peer.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * A struct element represent either a state or a method.
 */
struct element {
	struct list_head element_list;
	char *path;
	struct peer *peer; /*The peer the state belongs to */
	cJSON *value; /* NULL if method */
	const struct fetch **fetcher_table;
	group_t fetch_groups;
	group_t set_groups;
	group_t call_groups;
	int flags;
	double timeout;
	unsigned int fetch_table_size;
};

enum type { STATE, METHOD };

static const int FETCH_ONLY_FLAG = 0x01;

bool element_is_fetch_only(const struct element *e);
cJSON *change_state(const struct peer *p, const cJSON *request);
cJSON *set_or_call(const struct peer *p, const cJSON *request, enum type what);
cJSON *add_element_to_peer(struct peer *p, const cJSON *request);
cJSON *remove_element_from_peer(const struct peer *p, const cJSON *request);
void remove_all_elements_from_peer(struct peer *p);

#ifdef __cplusplus
}
#endif

#endif
