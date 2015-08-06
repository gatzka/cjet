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

#include "fetch.h"
#include "json/cJSON.h"
#include "list.h"
#include "peer.h"

#ifdef __cplusplus
extern "C" {
#endif

struct state {
	struct list_head state_list;
	char *path;
	struct peer *peer; /*The peer the state belongs to */
	cJSON *value;
	struct fetch **fetcher_table;
	double timeout;
	unsigned int fetch_table_size;
};

cJSON *change_state(struct peer *p, const char *path, const cJSON *value);
cJSON *set_state(struct peer *p, const char *path, const cJSON *value,
	const cJSON *json_rpc);
cJSON *add_state_to_peer(struct peer *p, const char *path, const cJSON *value);
int remove_state_from_peer(struct peer *p, const char *path);
void remove_all_states_from_peer(struct peer *p);

int create_state_hashtable(void);
void delete_state_hashtable(void);
struct state *get_state(const char *path);

#ifdef __cplusplus
}
#endif

#endif
