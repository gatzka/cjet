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

#include "compiler.h"
#include "config/io.h"
#include "hashtable.h"
#include "json/cJSON.h"
#include "peer.h"
#include "response.h"
#include "router.h"

DECLARE_HASHTABLE_UINT32(route_table, CONFIG_ROUTING_TABLE_ORDER, 2)

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

cJSON *create_routed_message(const char *path, const char *name,
	cJSON *value, int id)
{
	cJSON *message = cJSON_CreateObject();
	if (unlikely(message == NULL)) {
		return NULL;
	}

	cJSON *json_id = cJSON_CreateNumber(id);
	if (unlikely(json_id == NULL)) {
		goto error;
	}
	cJSON_AddItemToObject(message, "id", json_id);

	cJSON *method = cJSON_CreateString(path);
	if (unlikely(method == NULL)) {
		goto error;
	}
	cJSON_AddItemToObject(message, "method", method);

	cJSON *value_copy = cJSON_Duplicate(value, 1);
	if (unlikely(value_copy == NULL)) {
		goto error;
	}

	if (name == NULL) {
		cJSON_AddItemToObject(message, "params", value_copy);
	} else {
		cJSON *params = cJSON_CreateObject();
		if (unlikely(params == NULL)) {
			goto error;
		}
		cJSON_AddItemToObject(message, "params", params);

		cJSON_AddItemToObject(params, name, value_copy);
	}

	return message;

error:
	fprintf(stderr, "Could not allocate memory for %s object!\n", "routed");
	cJSON_Delete(message);
	return NULL;
}

int setup_routing_information(const struct peer *routing_peer,
	struct peer *origin_peer, cJSON *origin_request_id, int id)
{
	cJSON *id_copy;
	if (origin_request_id != NULL) {
		id_copy = cJSON_Duplicate(origin_request_id, 1);
		if (unlikely(id_copy == NULL)) {
			fprintf(stderr, "Could not copy value object!\n");
			return -1;
		}
	} else {
		id_copy = NULL;
	}
	struct value_route_table val;
	val.vals[0] = origin_peer;
	val.vals[1] = id_copy;
	if (unlikely(HASHTABLE_PUT(route_table, routing_peer->routing_table,
			id, val, NULL) != HASHTABLE_SUCCESS)) {
		cJSON_Delete(id_copy);
	}
	return 0;
}

static void format_and_send_response(struct peer *p, cJSON *response)
{
	char *rendered = cJSON_PrintUnformatted(response);
	if (likely(rendered != NULL)) {
		send_message(p, rendered, strlen(rendered));
		cJSON_free(rendered);
	} else {
		fprintf(stderr, "Could not render JSON into a string!\n");
	}
}

static void send_routing_response(struct peer *p,
	cJSON *origin_request_id, cJSON *response)
{
	if (origin_request_id == NULL) {
		return;
	}
	cJSON *response_copy = cJSON_Duplicate(response, 1);
	if (likely(response_copy != NULL)) {
		cJSON *result_response =
			create_result_response(origin_request_id, response_copy);
		if (likely(result_response != NULL)) {
			format_and_send_response(p, result_response);
			cJSON_Delete(result_response);
		} else {
			fprintf(stderr, "Could not create %s response!\n", "result");
			cJSON_Delete(response_copy);
		}
	}
}

int handle_routing_response(cJSON *json_rpc, cJSON *response,
	const struct peer *p)
{
	cJSON *id = cJSON_GetObjectItem(json_rpc, "id");
	if (unlikely(id == NULL)) {
		fprintf(stderr, "no id in response!\n");
		return -1;
	}
	if (unlikely(id->type != cJSON_Number)) {
		fprintf(stderr, "id is not a number!\n");
		return -1;
	}
	struct value_route_table val;
	int ret = HASHTABLE_REMOVE(route_table, p->routing_table, id->valueint, &val);
	if (likely(ret == HASHTABLE_SUCCESS)) {
		struct peer *origin_peer = val.vals[0];
		cJSON *origin_request_id = val.vals[1];
		send_routing_response(origin_peer, origin_request_id, response);
		cJSON_Delete(origin_request_id);
	}
	return ret;
}

static void send_shutdown_response(struct peer *p,
	cJSON *origin_request_id)
{
	if (origin_request_id == NULL) {
		return;
	}

	cJSON *error = create_internal_error("reason", "peer shuts down");
	if (likely(error != NULL)) {
		cJSON *error_response =
			create_error_response(origin_request_id, error);
		if (likely(error_response != NULL)) {
			format_and_send_response(p, error_response);
			cJSON_Delete(error_response);
		} else {
			fprintf(stderr, "Could not create %s response!\n", "error");
			cJSON_Delete(error);
		}
	}
}

void remove_peer_from_routing_table(const struct peer *p,
	const struct peer *peer_to_remove)
{
	struct hashtable_uint32_t *table = p->routing_table;
	for (unsigned int i = 0; i < table_size_route_table; ++i) {
		struct hashtable_uint32_t *entry = &(table[i]);
		if (entry->key != (uint32_t)HASHTABLE_INVALIDENTRY) {
			struct value_route_table val;
			int ret = HASHTABLE_GET(route_table,
					p->routing_table, entry->key, &val);
			if (ret == HASHTABLE_SUCCESS) {
				struct peer *origin_peer = val.vals[0];
				if (origin_peer == peer_to_remove) {
					cJSON *origin_request_id = val.vals[1];
					send_shutdown_response(origin_peer, origin_request_id);
					HASHTABLE_REMOVE(route_table, p->routing_table, entry->key, &val);
					cJSON_Delete(origin_request_id);
				}
			}
		}
	}
}

void remove_routing_info_from_peer(const struct peer *p)
{
	struct hashtable_uint32_t *table = p->routing_table;
	for (unsigned int i = 0; i < table_size_route_table; ++i) {
		struct hashtable_uint32_t *entry = &(table[i]);
		if (entry->key != (uint32_t)HASHTABLE_INVALIDENTRY) {
			struct value_route_table val;
			int ret = HASHTABLE_REMOVE(route_table,
					p->routing_table, entry->key, &val);
			if (ret == HASHTABLE_SUCCESS) {
				struct peer *origin_peer = val.vals[0];
				cJSON *origin_request_id = val.vals[1];
				send_shutdown_response(origin_peer, origin_request_id);
				cJSON_Delete(origin_request_id);
			}
		}
	}
}

