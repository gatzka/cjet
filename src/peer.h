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

#ifndef CJET_PEER_H
#define CJET_PEER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "eventloop.h"
#include "groups.h"
#include "list.h"
#include "cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

struct peer {
	struct list_head element_list;
	struct list_head next_peer;
	struct list_head fetch_list;
	void *routing_table;
	char *name;
	int (*send_message)(const struct peer *p, char *rendered, size_t len);
	void (*close)(struct peer *p);
	struct eventloop *loop;
	group_t fetch_groups;
	group_t set_groups;
	group_t call_groups;
	char *user_name;
	bool is_local_connection;
};

int init_peer(struct peer *p, bool is_local_connection, struct eventloop *loop);
void free_peer_resources(struct peer *p);
const struct list_head *get_peer_list(void);
void set_peer_name(struct peer *peer, const char *name);
const char *get_peer_name(const struct peer *p);
int get_number_of_peers(void);
void log_peer_info(const struct peer *p, const char *fmt, ...);
void log_peer_err(const struct peer *p, const char *fmt, ...);
void destroy_all_peers(void);

#ifdef __cplusplus
}
#endif

#endif
