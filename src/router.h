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

#ifndef CJET_ROUTER_H
#define CJET_ROUTER_H

#include "json/cJSON.h"
#include "peer.h"
#include "state.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ROUTED_MESSAGE -1

cJSON *create_routed_message(const struct peer *p, const char *path, enum type what,
	const cJSON *value, const char *id);
int setup_routing_information(struct state_or_method *s,
	struct peer *origin_peer, const cJSON *origin_request_id, char *id);
struct routing_request *alloc_routing_request(const struct peer *p, const cJSON *origin_request_id);
int handle_routing_response(const cJSON *json_rpc, const cJSON *response, const char *result_type,
	const struct peer *p);

void remove_routing_info_from_peer(const struct peer *p);
void remove_peer_from_routing_table(const struct peer *p,
	const struct peer *peer_to_remove);

int add_routing_table(struct peer *p);
void delete_routing_table(struct peer *p);

#ifdef __cplusplus
}
#endif

#endif
