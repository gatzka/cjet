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

#include <stdbool.h>
#include <string.h>

#include "alloc.h"
#include "compiler.h"
#include "element.h"
#include "generated/cjet_config.h"
#include "groups.h"
#include "hashtable.h"
#include "jet_string.h"
#include "json/cJSON.h"
#include "linux/linux_io.h"
#include "list.h"
#include "peer.h"
#include "request.h"
#include "response.h"
#include "router.h"
#include "table.h"
#include "uuid.h"

static bool is_state(const struct element *e)
{
	return (e->value != NULL);
}

#define FILL_GROUP(access_groups, json_key) \
static cJSON *fill_##access_groups(struct element *e, const struct peer *p, const cJSON *request, const cJSON *access) \
{ \
	if (access == NULL) { \
		return NULL; \
	} \
\
	const cJSON *groups = cJSON_GetObjectItem(access, json_key); \
	if ((groups != NULL) && (groups->type != cJSON_Array)) { \
		return create_error_response_from_request(p, request, INVALID_PARAMS, "reason", #access_groups" is not an array"); \
	} \
\
	e->access_groups = get_groups(groups); \
\
	return NULL; \
}

FILL_GROUP(fetch_groups, "fetchGroups")
FILL_GROUP(set_groups, "setGroups")
FILL_GROUP(call_groups, "callGroups")

static cJSON *fill_access(struct element *e, const cJSON *request, const struct peer *p, const cJSON *access)
{
	cJSON *error = fill_fetch_groups(e, p, request, access);
	if (error != NULL) {
		return error;
	}

	if (is_state(e)) {
		error = fill_set_groups(e, p, request, access);
		if (error != NULL) {
			return error;
		}
	} else {
		error = fill_call_groups(e, p, request, access);
		if (error != NULL) {
			return error;
		}
	}

	return NULL;
}

static const char *get_path_from_params(const struct peer *p, const cJSON *request, const cJSON *params, cJSON **response)
{
	const cJSON *path = cJSON_GetObjectItem(params, "path");
	if (unlikely(path == NULL)) {
		*response = create_error_response_from_request(p, request, INVALID_PARAMS, "reason", "no path given");
		return NULL;
	}

	if (unlikely(path->type != cJSON_String)) {
		*response = create_error_response_from_request(p, request, INVALID_PARAMS, "reason", "path is not a string");
	}

	return path->valuestring;
}

static int get_fetch_only_from_params(const struct peer *p, const cJSON *request, const cJSON *params, cJSON **err)
{
	const cJSON *fetch_only = cJSON_GetObjectItem(params, "fetchOnly");
	if (fetch_only == NULL || (fetch_only->type == cJSON_False)) {
		*err = NULL;
		return 0;
	}

	if (fetch_only->type == cJSON_True) {
		*err = NULL;
		return FETCH_ONLY_FLAG;
	}

	*err = create_error_response_from_request(p, request, INVALID_PARAMS, "reason", "fetchOnly is not a bool");
	return 0;
}

static cJSON *init_element(struct element *e, const cJSON *request, struct peer *p)
{

	cJSON *response = NULL;
	const cJSON *params = get_params(p, request, &response);
	if (unlikely(params == NULL)) {
		return response;
	}

	const char *path = get_path_from_params(p, request, params, &response);
	if (unlikely(path == NULL)) {
		return response;
	}

	int flags = get_fetch_only_from_params(p, request, params, &response);
	if (unlikely(response != NULL)) {
		return response;
	}

	const cJSON *timeout = cJSON_GetObjectItem(params, "timeout");
	double routed_request_timeout_s;
	if (timeout != NULL) {
		if (unlikely(timeout->type != cJSON_Number)) {
			return create_error_response_from_request(p, request, INVALID_PARAMS, "reason", "timeout must be a number");
		} else {
			routed_request_timeout_s = timeout->valuedouble;
			if (unlikely(routed_request_timeout_s < 0)) {
				return create_error_response_from_request(p, request, INVALID_PARAMS, "reason", "timeout must be positive");
			}
		}
	} else {
		routed_request_timeout_s = CONFIG_ROUTED_MESSAGES_TIMEOUT;
	}

	if (unlikely(element_table_get(path) != NULL)) {
		return create_error_response_from_request(p, request, INVALID_PARAMS, "exists", path);
	}
	const cJSON *value = cJSON_GetObjectItem(params, "value");
	const cJSON *access = cJSON_GetObjectItem(params, "access");

	e->flags = flags;
	e->timeout = routed_request_timeout_s;
	e->fetch_table_size = CONFIG_INITIAL_FETCH_TABLE_SIZE;
	e->fetcher_table = cjet_calloc(e->fetch_table_size, sizeof(struct fetch *));
	if (e->fetcher_table == NULL) {
		log_peer_err(p, "Could not allocate memory for fetch table!\n");
		return create_error_response_from_request(p, request, INTERNAL_ERROR, "reason", "not enough memory to create fetch table");
	}

	e->path = duplicate_string(path);
	if (unlikely(e->path == NULL)) {
		log_peer_err(p, "Could not allocate memory for %s object!\n", "path");
		response = create_error_response_from_request(p, request, INTERNAL_ERROR, "reason", "not enough memory to copy path");
		goto alloc_path_failed;
	}

	if (value != NULL) {
		cJSON *value_copy = cJSON_Duplicate(value, 1);
		if (unlikely(value_copy == NULL)) {
			log_peer_err(p, "Could not copy value object!\n");
			response = create_error_response_from_request(p, request, INTERNAL_ERROR, "reason", "not enough memory to copy value");
			goto value_copy_failed;
		}
		e->value = value_copy;
	}

	INIT_LIST_HEAD(&e->element_list);
	e->peer = p;

	response = fill_access(e, request, p, access);
	if (response != NULL) {
		log_peer_err(p, "Could not fill access information!\n");
		goto fill_access_failed;
	}

	return NULL;

fill_access_failed:
	if (e->value != NULL) {
		cJSON_Delete(e->value);
	}
value_copy_failed:
	cjet_free(e->path);
alloc_path_failed:
	cjet_free(e->fetcher_table);
	return response;
}

static struct element *alloc_element(const struct peer *p)
{
	struct element *e = cjet_calloc(1, sizeof(*e));
	if (unlikely(e == NULL)) {
		log_peer_err(p, "Could not allocate memory for %s object!\n",
				 "element");
	}

	return e;
}

static void free_element(struct element *e)
{
	if (e->value != NULL) {
		cJSON_Delete(e->value);
	}

	cjet_free(e->path);
	cjet_free(e->fetcher_table);
	cjet_free(e);
}

bool element_is_fetch_only(const struct element *e)
{
	if ((e->flags & FETCH_ONLY_FLAG) == FETCH_ONLY_FLAG) {
		return true;
	} else {
		return false;
	}
}

cJSON *change_state(const struct peer *p, const cJSON *request)
{
	cJSON *response = NULL;

	const cJSON *params = get_params(p, request, &response);
	if (unlikely(params == NULL)) {
		return response;
	}

	const char *path = get_path_from_params(p, request, params, &response);
	if (unlikely(path == NULL)) {
		return response;
	}

	const cJSON *value = cJSON_GetObjectItem(params, "value");
	if (unlikely(value == NULL)) {
		return create_error_response_from_request(p, request, INVALID_PARAMS, "reason", "no value found");
	}

	struct element *e = element_table_get(path);
	if (unlikely(e == NULL)) {
		return create_error_response_from_request(p, request, INVALID_PARAMS, "not exists", path);
	}

	if (unlikely(e->peer != p)) {
		return create_error_response_from_request(p, request, INVALID_PARAMS, "not owner of state", path);
	}

	if (unlikely(e->value == NULL)) {
		return create_error_response_from_request(p, request, INVALID_PARAMS, "change on method not possible", path);
	}

	cJSON *value_copy = cJSON_Duplicate(value, 1);
	if (value_copy == NULL) {
		return create_error_response_from_request(p, request, INTERNAL_ERROR, "not enough memory", path);
	}

	cJSON_Delete(e->value);
	e->value = value_copy;
	if (unlikely(notify_fetchers(e, "change") != 0)) {
		return create_error_response_from_request(p, request, INTERNAL_ERROR, "could not notify fetching peer", path);
	}

	return create_success_response_from_request(p, request);
}

cJSON *set_or_call(const struct peer *p, const cJSON *request, enum type what)
{
	cJSON *response = NULL;

	const cJSON *params = get_params(p, request, &response);
	if (unlikely(params == NULL)) {
		return response;
	}

	const char *path = get_path_from_params(p, request, params, &response);
	if (unlikely(path == NULL)) {
		return response;
	}

	struct element *e = element_table_get(path);
	if (unlikely(e == NULL)) {
		return create_error_response_from_request(p, request, INVALID_PARAMS, "not exists", path);
	}

	if (unlikely(element_is_fetch_only(e))) {
		return create_error_response_from_request(p, request, INVALID_PARAMS, "fetchOnly", path);
	}

	if (unlikely(((what == STATE) && (e->value == NULL)) ||
		((what == METHOD) && (e->value != NULL)))) {
			return create_error_response_from_request(p, request, INVALID_PARAMS, "set/call on element not possible", path);
	}

	if (((what == STATE) && (!has_access(e->set_groups, p->set_groups))) ||
		((what == METHOD) && (!has_access(e->call_groups, p->call_groups)))) {
		return create_error_response_from_request(p, request, INVALID_PARAMS, "request not authorized", path);
	}

	const cJSON *origin_request_id = cJSON_GetObjectItem(request, "id");
	if ((origin_request_id != NULL) &&
		((origin_request_id->type != cJSON_String) &&
		 (origin_request_id->type != cJSON_Number))) {
		return create_error_response_from_request(p, request, INVALID_PARAMS, "request id is neither string nor number", path);
	}

	struct routing_request *routing_request = alloc_routing_request(p, e->peer, origin_request_id);
	if (unlikely(routing_request == NULL)) {
		return create_error_response_from_request(p, request, INTERNAL_ERROR, "could not create routing request", path);
	}

	const cJSON *value;
	if (what == STATE) {
		value = cJSON_GetObjectItem(params, "value");
		if (unlikely(value == NULL)) {
			return create_error_response_from_request(p, request, INVALID_PARAMS, "reason", "no value found");
		}
	} else {
		value = cJSON_GetObjectItem(params, "args");
	}

	cJSON *routed_message = create_routed_message(p, path, what, value, routing_request->id);
	if (unlikely(routed_message == NULL)) {
		response = create_error_response_from_request(p, request, INTERNAL_ERROR, "reason", "could not create routed JSON object");
		goto routed_message_creation_failed;
	}

	const cJSON *timeout = cJSON_GetObjectItem(params, "timeout");
	response = setup_routing_information(e, request, timeout, routing_request);
	if (unlikely(response != NULL)) {
		goto delete_json;
	}

	char *rendered_message = cJSON_PrintUnformatted(routed_message);
	if (unlikely(rendered_message == NULL)) {
		response = create_error_response_from_request(p, request, INTERNAL_ERROR, "reason", "could not render message");
		goto delete_json;
	}

	if (unlikely(e->peer->send_message(e->peer, rendered_message,
				 strlen(rendered_message)) != 0)) {
		response = create_error_response_from_request(p, request, INTERNAL_ERROR, "reason", "could not send routing information");
	}

	cjet_free(rendered_message);
	cJSON_Delete(routed_message);
	return response;

delete_json:
	cJSON_Delete(routed_message);
routed_message_creation_failed:
	cJSON_Delete(routing_request->origin_request_id);
	cjet_free(routing_request);
	return response;
}

cJSON *add_element_to_peer(struct peer *p, const cJSON *request)
{
	if (CONFIG_ALLOW_ADD_ONLY_FROM_LOCALHOST) {
		if (!p->is_local_connection) {
			return create_error_response_from_request(p, request, INVALID_REQUEST, "reason", "add only allowed from localhost");
		}
	}

	struct element *e = alloc_element(p);
	if (unlikely(e == NULL)) {
		return create_error_response_from_request(p, request, INTERNAL_ERROR, "reason", "not enough memory to allocate jet element");
	}

	cJSON *response = init_element(e, request, p);
	if (unlikely(response != NULL)) {
		cjet_free(e);
		return response;
	}

	if (unlikely(find_fetchers_for_element(e) != 0)) {
		free_element(e);
		return create_error_response_from_request(p, request, INTERNAL_ERROR, "reason", "could not notify fetching peer");
	}

	if (unlikely(element_table_put(e->path, e) != HASHTABLE_SUCCESS)) {
		free_element(e);
		return create_error_response_from_request(p, request, INTERNAL_ERROR, "reason", "element table full");
	}

	list_add_tail(&e->element_list, &p->element_list);

	return create_success_response_from_request(p, request);
}

static void remove_element(struct element *e)
{
	notify_fetchers(e, "remove");
	list_del(&e->element_list);
	element_table_remove(e->path);
	free_element(e);
}

cJSON *remove_element_from_peer(const struct peer *p, const cJSON *request)
{
	cJSON *response = NULL;
	const cJSON *params = get_params(p, request, &response);
	if (unlikely(params == NULL)) {
		return response;
	}

	const char *path = get_path_from_params(p, request, params, &response);
	if (unlikely(path == NULL)) {
		return response;
	}

	struct list_head *item;
	struct list_head *tmp;
	list_for_each_safe(item, tmp, &p->element_list)
	{
		struct element *e = list_entry(item, struct element, element_list);
		if (strcmp(e->path, path) == 0) {
			remove_element(e);
			return create_success_response_from_request(p, request);
		}
	}

	return create_error_response_from_request(p, request, INVALID_PARAMS, "not exists", path);
}

void remove_all_elements_from_peer(struct peer *p)
{
	struct list_head *item;
	struct list_head *tmp;
	list_for_each_safe(item, tmp, &p->element_list)
	{
		struct element *e = list_entry(item, struct element, element_list);
		remove_element(e);
	}
}
