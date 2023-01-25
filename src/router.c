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

#include <stddef.h>
#include <stdio.h>

#include "alloc.h"
#include "compiler.h"
#include "generated/cjet_config.h"
#include "hashtable.h"
#include "linux/linux_io.h"
#include "peer.h"
#include "response.h"
#include "router.h"
#include "timer.h"
#include "json/cJSON.h"

/* incremented with each request */
static unsigned int uuid = 0;

static size_t calculate_size_for_routed_request_id(const void *address, const cJSON *origin_request_id)
{
	if (origin_request_id != NULL) {
		return snprintf(NULL, 0, "%s_%x_%p", origin_request_id->valuestring, uuid, address);
	} else {
		return snprintf(NULL, 0, "%x_%p", uuid, address);
	}
}

static void fill_routed_request_id(char *buf, size_t buf_size, const void *address, const cJSON *origin_request_id)
{
	if (origin_request_id != NULL) {
		snprintf(buf, buf_size, "%s_%x_%p", origin_request_id->valuestring, uuid, address);
	} else {
		snprintf(buf, buf_size, "%x_%p", uuid, address);
	}
	uuid++;
}

DECLARE_HASHTABLE_STRING(route_table, CONFIG_ROUTING_TABLE_ORDER, 1)

int add_routing_table(struct peer *p)
{
	p->routing_table = HASHTABLE_CREATE(route_table);
	if (unlikely(p->routing_table == NULL)) {
		return -1;
	} else {
		return 0;
	}
}

void delete_routing_table(struct peer *p)
{
	HASHTABLE_DELETE(route_table, p->routing_table);
}

cJSON *create_routed_message(const struct peer *p, const char *path, enum type what,
                             const cJSON *value, const char *id)
{
	cJSON *message = cJSON_CreateObject();
	if (unlikely(message == NULL)) {
		return NULL;
	}

	cJSON *json_id = cJSON_CreateString(id);
	if (unlikely(json_id == NULL)) {
		goto error;
	}
	cJSON_AddItemToObject(message, "id", json_id);

	cJSON *method = cJSON_CreateString(path);
	if (unlikely(method == NULL)) {
		goto error;
	}
	cJSON_AddItemToObject(message, "method", method);

	cJSON *value_copy;
	if (value != NULL) {
		value_copy = cJSON_Duplicate(value, 1);
	} else {
		value_copy = cJSON_CreateObject();
	}
	if (unlikely(value_copy == NULL)) {
		goto error;
	}

	if (what == METHOD) {
		cJSON_AddItemToObject(message, "params", value_copy);
	} else {
		cJSON *params = cJSON_CreateObject();
		if (unlikely(params == NULL)) {
			goto error;
		}
		cJSON_AddItemToObject(message, "params", params);
		cJSON_AddItemToObject(params, "value", value_copy);
	}

	return message;

error:
	log_peer_err(p, "Could not allocate memory for %s object!\n", "routed");
	cJSON_Delete(message);
	return NULL;
}

struct routing_request *alloc_routing_request(const struct peer *requesting_peer, const struct peer *owner_peer, const cJSON *origin_request_id)
{
	struct routing_request *request;

	size_t size_for_id = calculate_size_for_routed_request_id(requesting_peer, origin_request_id);
	request = (struct routing_request *)cjet_malloc(sizeof(*request) + size_for_id);
	if (likely(request != NULL)) {
		cJSON *origin_request_id_copy;
		if (origin_request_id != NULL) {
			origin_request_id_copy = cJSON_Duplicate(origin_request_id, 1);
			if (unlikely(origin_request_id_copy == NULL)) {
				log_peer_err(requesting_peer, "Could not copy origin_request_id object!\n");
				goto duplicate_id_failed;
			}
		} else {
			origin_request_id_copy = NULL;
		}

		request->requesting_peer = requesting_peer;
		request->owner_peer = owner_peer;
		request->origin_request_id = origin_request_id_copy;
		fill_routed_request_id(request->id, size_for_id, requesting_peer, origin_request_id);
	}

	return request;

duplicate_id_failed:
	cjet_free(request);
	return NULL;
}

static int format_and_send_response(const struct peer *p, const cJSON *response)
{
	char *rendered = cJSON_PrintUnformatted(response);
	if (likely(rendered != NULL)) {
		int ret = p->send_message(p, rendered, strlen(rendered));
		cjet_free(rendered);
		return ret;
	} else {
		log_peer_err(p, "Could not render JSON into a string!\n");
		return -1;
	}
}

/**
 * @param context Routing request that got timed out. 
 * The function is responsible to destroy it and all its contents!
 * @param cancelled If true timeout timer got cancelled because response arrived in time
 */
static void request_timeout_handler(void *context, bool cancelled)
{
	if (likely(cancelled)) {
		return;
	}

	struct routing_request *request = (struct routing_request *)context;
	int ret = HASHTABLE_REMOVE(route_table, request->owner_peer->routing_table, request->id, NULL);
	if (unlikely(ret != HASHTABLE_SUCCESS)) {
		log_peer_err(request->requesting_peer, "request_timeout_handler: Hashtable remove not successful");
	}
	
	if (likely(request->origin_request_id != NULL)) {
		cJSON *result_response = create_error_response(request->requesting_peer, request->origin_request_id, INTERNAL_ERROR, "reason", "timeout for routed request");
		if (likely(result_response != NULL)) {
			format_and_send_response(request->requesting_peer, result_response);
			cJSON_Delete(result_response);
		} else {
			log_peer_err(request->requesting_peer, "request_timeout_handler: Could not create error response!");
		}
	}
	
	cjet_timer_destroy(&request->timer);
	cJSON_Delete(request->origin_request_id);
	cjet_free(request);
}

int setup_routing_information(struct element *e, const cJSON *request, const cJSON *timeout, struct routing_request *routing_request, cJSON **response)
{
	uint64_t timeout_ns = get_timeout_in_nsec(routing_request->requesting_peer, request, timeout, response, e->timeout_nsec);
	if (unlikely(timeout_ns == 0)) {
		return -1;
	}

	if (unlikely(cjet_timer_init(&routing_request->timer, e->peer->loop) < 0)) {
		*response = create_error_response_from_request(routing_request->requesting_peer, request, INTERNAL_ERROR, "reason", "could not init timer for routing request");
		return -1;
	}

	struct value_route_table val;
	val.vals[0] = routing_request;
	if (unlikely(HASHTABLE_PUT(route_table, e->peer->routing_table, routing_request->id, val, NULL) != HASHTABLE_SUCCESS)) {
		*response = create_error_response_from_request(routing_request->requesting_peer, request, INTERNAL_ERROR, "reason", "routing table full");
		return -1;
	}

	int ret = routing_request->timer.start(&routing_request->timer, timeout_ns, request_timeout_handler, routing_request);
	if (unlikely(ret < 0)) {
		HASHTABLE_REMOVE(route_table, e->peer->routing_table, routing_request->id, NULL);
		*response = create_error_response_from_request(routing_request->requesting_peer, request, INTERNAL_ERROR, "reason", "could not start timer for routing request");
		return -1;
	}
	return 0;
}

/**
 * @param json_rpc The complete response
 * @param response Result or error object of json_rpc, this is what is to be forwarded to the original requester
 * @param result_type Tells whether response is result or error
 * @param p The peer that does the routing of the original request
 * to the original requester
 */
int handle_routing_response(const cJSON *json_rpc, const cJSON *response, const char *result_type,
                            const struct peer *p)
{
	const cJSON *id = cJSON_GetObjectItem(json_rpc, "id");
	if (unlikely(id == NULL)) {
		log_peer_err(p, "no id in response!\n");
		return -1;
	}

	if (unlikely(id->type != cJSON_String)) {
		log_peer_err(p, "id is not a string!\n");
		return -1;
	}

	struct value_route_table val;
	int ret = HASHTABLE_REMOVE(route_table, p->routing_table, id->valuestring, &val);
	if (likely(ret == HASHTABLE_SUCCESS)) {
		struct routing_request *request = (struct routing_request *)val.vals[0];
		if (unlikely(request->timer.cancel(&request->timer) < 0)) {
			log_peer_err(p, "Could not cancel request timer!\n");
		}

		cjet_timer_destroy(&request->timer);
		if (likely(request->origin_request_id != NULL)) {
			cJSON *response_copy = cJSON_Duplicate(response, 1);
			if (likely(response_copy != NULL)) {
				cJSON *result_response = create_result_response(request->requesting_peer, request->origin_request_id, response_copy, result_type);
				if (likely(result_response != NULL)) {
					format_and_send_response(request->requesting_peer, result_response);
					cJSON_Delete(result_response);
				} else {
					log_peer_err(request->requesting_peer, "Could not create %s response!\n", result_type);
					cJSON_Delete(response_copy);
				}
			} else {
				log_peer_err(p, "Could not copy response!\n");
				ret = -1;
			}
			cJSON_Delete(request->origin_request_id);
		}

		cjet_free(request);
		return ret;
	} else {
		return 0;
	}
}

static void send_shutdown_response(const struct peer *p,
                                   const cJSON *origin_request_id)
{
	if (origin_request_id == NULL) {
		return;
	}

	cJSON *error_response = create_error_response(p, origin_request_id, INTERNAL_ERROR, "reason", "peer shuts down");
	if (likely(error_response != NULL)) {
		format_and_send_response(p, error_response);
		cJSON_Delete(error_response);
	} else {
		log_peer_err(p, "Could not create %s response!\n", "error");
	}
}

static void clear_routing_entry(struct value_route_table *val)
{
	struct routing_request *request = val->vals[0];

	if (unlikely(request->timer.cancel(&request->timer) < 0)) {
		log_peer_err(request->requesting_peer, "Could not cancel request timer when clearing routing entry!\n");
	}

	send_shutdown_response(request->requesting_peer, request->origin_request_id);
	cJSON_Delete(request->origin_request_id);
	cjet_free(request);
}

void remove_peer_from_routing_table(const struct peer *p,
                                    const struct peer *peer_to_remove)
{
	struct hashtable_string *table = p->routing_table;
	for (unsigned int i = 0; i < table_size_route_table; ++i) {
		struct hashtable_string *entry = &(table[i]);
		if (entry->key != (char *)HASHTABLE_INVALIDENTRY) {
			struct value_route_table val;
			int ret = HASHTABLE_REMOVE(route_table, p->routing_table, entry->key, &val);
			if (ret == HASHTABLE_SUCCESS) {
				struct routing_request *request = val.vals[0];
				if (likely(request->requesting_peer == peer_to_remove)) {
					clear_routing_entry(&val);
				}
			}
		}
	}
}

void remove_routing_info_from_peer(const struct peer *p)
{
	struct hashtable_string *table = p->routing_table;
	for (unsigned int i = 0; i < table_size_route_table; ++i) {
		struct hashtable_string *entry = &(table[i]);
		if (entry->key != (char *)HASHTABLE_INVALIDENTRY) {
			struct value_route_table val;
			int ret = HASHTABLE_REMOVE(route_table,
			                           p->routing_table, entry->key, &val);
			if (ret == HASHTABLE_SUCCESS) {
				clear_routing_entry(&val);
			}
		}
	}
}
