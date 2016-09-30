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

#include "alloc.h"
#include "compiler.h"
#include "hashtable.h"
#include "json/cJSON.h"
#include "linux/linux_io.h"
#include "peer.h"
#include "response.h"
#include "router.h"

DECLARE_HASHTABLE_STRING(route_table, CONFIG_ROUTING_TABLE_ORDER, 3)

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

int setup_routing_information(struct state_or_method *s,
	struct peer *origin_peer, const cJSON *origin_request_id, char *id)
{
	cJSON *id_copy;
	if (origin_request_id != NULL) {
		id_copy = cJSON_Duplicate(origin_request_id, 1);
		if (unlikely(id_copy == NULL)) {
			log_peer_err(origin_peer, "Could not copy origin_request_id object!\n");
			goto id_copy_error;
		}
	} else {
		id_copy = NULL;
	}
	struct value_route_table val;
	val.vals[0] = origin_peer;
	val.vals[1] = id_copy;
	val.vals[2] = id;
	if (unlikely(HASHTABLE_PUT(route_table, s->peer->routing_table,
			id, val, NULL) != HASHTABLE_SUCCESS)) {
		log_peer_err(origin_peer, "Routing table full!\n");
		goto hash_put_error;
	}
	return 0;

hash_put_error:
	cJSON_Delete(id_copy);
id_copy_error:
	return -1;
}

static int format_and_send_response(struct peer *p, const cJSON *response)
{
	char *rendered = cJSON_PrintUnformatted(response);
	if (likely(rendered != NULL)) {
		int ret = p->send_message(p, rendered, strlen(rendered));
		cJSON_free(rendered);
		return ret;
	} else {
		log_peer_err(p, "Could not render JSON into a string!\n");
		return -1;
	}
}

static int send_routing_response(struct peer *p,
	const cJSON *origin_request_id, const cJSON *response, const char *result_type)
{
	if (unlikely(origin_request_id == NULL)) {
		return 0;
	}
	cJSON *response_copy = cJSON_Duplicate(response, 1);
	if (likely(response_copy != NULL)) {
		cJSON *result_response =
			create_result_response(p, origin_request_id, response_copy, result_type);
		if (likely(result_response != NULL)) {
			int ret = format_and_send_response(p, result_response);
			cJSON_Delete(result_response);
			return ret;
		} else {
			log_peer_err(p, "Could not create %s response!\n", result_type);
			cJSON_Delete(response_copy);
			return -1;
		}
	} else {
		log_peer_err(p, "Could not allocate memory for %s object!\n", "response_copy");
		return -1;
	}

	return 0;
}

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
		struct peer *origin_peer = val.vals[0];
		cJSON *origin_request_id = val.vals[1];
		char *routed_id = val.vals[2];
		ret = send_routing_response(origin_peer, origin_request_id, response, result_type);
		cJSON_Delete(origin_request_id);
		cjet_free(routed_id);
	}
	return ret;
}

static void send_shutdown_response(struct peer *p,
	const cJSON *origin_request_id)
{
	if (origin_request_id == NULL) {
		return;
	}

	cJSON *error = create_internal_error(p, "reason", "peer shuts down");
	if (likely(error != NULL)) {
		cJSON *error_response =
			create_error_response(p, origin_request_id, error);
		if (likely(error_response != NULL)) {
			format_and_send_response(p, error_response);
			cJSON_Delete(error_response);
		} else {
			log_peer_err(p, "Could not create %s response!\n", "error");
			cJSON_Delete(error);
		}
	}
}

static void clear_routing_entry(struct value_route_table *val)
{
	struct peer *origin_peer = val->vals[0];

	cJSON *origin_request_id = val->vals[1];
	char *id = val->vals[2];

	send_shutdown_response(origin_peer, origin_request_id);
	cJSON_Delete(origin_request_id);
	cjet_free(id);
}

void remove_peer_from_routing_table(const struct peer *p,
	const struct peer *peer_to_remove)
{
	struct hashtable_string *table = p->routing_table;
	for (unsigned int i = 0; i < table_size_route_table; ++i) {
		struct hashtable_string *entry = &(table[i]);
		if (entry->key != (char *)HASHTABLE_INVALIDENTRY) {
			struct value_route_table val;
			int ret = HASHTABLE_GET(route_table,
					p->routing_table, entry->key, &val);
			if (ret == HASHTABLE_SUCCESS) {
				struct peer *origin_peer = val.vals[0];
				if (origin_peer == peer_to_remove) {
					HASHTABLE_REMOVE(route_table, p->routing_table, entry->key, NULL);
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
