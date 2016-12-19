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
#include "generated/cjet_config.h"
#include "groups.h"
#include "hashtable.h"
#include "jet_string.h"
#include "json/cJSON.h"
#include "linux/linux_io.h"
#include "list.h"
#include "peer.h"
#include "response.h"
#include "router.h"
#include "state.h"
#include "table.h"
#include "uuid.h"

static bool is_state(const struct element *e)
{
	return (e->value != NULL);
}

#define FILL_GROUP(access_groups, json_key) \
static cJSON *fill_##access_groups(struct element *e, const struct peer *p, const cJSON *access) \
{ \
	if (access == NULL) { \
		return NULL; \
	} \
\
	const cJSON *groups = cJSON_GetObjectItem(access, json_key); \
	if ((groups != NULL) && (groups->type != cJSON_Array)) { \
		cJSON *error = create_invalid_params_error(p, "reason", #access_groups" is not an array"); \
		return error; \
	} \
\
	e->access_groups = get_groups(groups); \
\
	return NULL; \
}

FILL_GROUP(fetch_groups, "fetchGroups")
FILL_GROUP(set_groups, "setGroups")
FILL_GROUP(call_groups, "callGroups")

static cJSON *fill_access(struct element *e, const struct peer *p, const cJSON *access)
{
	cJSON *error = fill_fetch_groups(e, p, access);
	if (error != NULL) {
		return error;
	}

	if (is_state(e)) {
		error = fill_set_groups(e, p, access);
		if (error != NULL) {
			return error;
		}
	} else {
		error = fill_call_groups(e, p, access);
		if (error != NULL) {
			return error;
		}
	}

	return NULL;
}

static cJSON *init_state(struct element *e, const char *path, const cJSON *value_object, const cJSON *access,
						 struct peer *p, double timeout, int flags)
{
	cJSON *error = NULL;

	e->flags = flags;
	e->timeout = timeout;
	e->fetch_table_size = CONFIG_INITIAL_FETCH_TABLE_SIZE;
	e->fetcher_table = cjet_calloc(e->fetch_table_size, sizeof(struct fetch *));
	if (e->fetcher_table == NULL) {
		log_peer_err(p, "Could not allocate memory for fetch table!\n");
		error =	create_internal_error(p, "reason", "not enough memory to create fetch table");
		return error;
	}

	e->path = duplicate_string(path);
	if (unlikely(e->path == NULL)) {
		log_peer_err(p, "Could not allocate memory for %s object!\n", "path");
		error =	create_internal_error(p, "reason", "not enough memory to copy path");
		goto alloc_path_failed;
	}

	if (value_object != NULL) {
		cJSON *value_copy = cJSON_Duplicate(value_object, 1);
		if (unlikely(value_copy == NULL)) {
			log_peer_err(p, "Could not copy value object!\n");
			error =	create_internal_error(p, "reason", "not enough memory to copy value");
			goto value_copy_failed;
		}
		e->value = value_copy;
	}

	INIT_LIST_HEAD(&e->state_list);
	e->peer = p;

	error = fill_access(e, p, access);
	if (error != NULL) {
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
	return error;
}

static struct element *alloc_state(const struct peer *p)
{
	struct element *e = cjet_calloc(1, sizeof(*e));
	if (unlikely(e == NULL)) {
		log_peer_err(p, "Could not allocate memory for %s object!\n",
				 "state");
	}

	return e;
}

static void free_state_or_method(struct element *e)
{
	if (e->value != NULL) {
		cJSON_Delete(e->value);
	}

	cjet_free(e->path);
	cjet_free(e->fetcher_table);
	cjet_free(e);
}

bool state_is_fetch_only(struct element *e)
{
	if ((e->flags & FETCH_ONLY_FLAG) == FETCH_ONLY_FLAG) {
		return true;
	} else {
		return false;
	}
}

cJSON *change_state(const struct peer *p, const char *path, const cJSON *value)
{
	struct element *e = state_table_get(path);
	if (unlikely(e == NULL)) {
		cJSON *error =
			create_invalid_params_error(p, "not exists", path);
		return error;
	}
	if (unlikely(e->peer != p)) {
		cJSON *error =
			create_invalid_params_error(p, "not owner of state", path);
		return error;
	}
	if (unlikely(e->value == NULL)) {
		cJSON *error =
			create_invalid_params_error(p, "change on method not possible", path);
		return error;
	}
	cJSON *value_copy = cJSON_Duplicate(value, 1);
	if (value_copy == NULL) {
		cJSON *error =
			create_internal_error(p, "reason", "not enough memory");
		return error;
	}
	cJSON_Delete(e->value);
	e->value = value_copy;
	if (unlikely(notify_fetchers(e, "change") != 0)) {
		cJSON *error = create_internal_error(
			p, "reason", "Can't notify fetching peer");
		return error;
	}
	return NULL;
}

cJSON *set_or_call(const struct peer *p, const char *path, const cJSON *value,
		const cJSON *timeout, const cJSON *json_rpc, enum type what)
{
	cJSON *error;
	struct element *e = state_table_get(path);
	if (unlikely(e == NULL)) {
		error = create_invalid_params_error(p, "not exists", path);
		return error;
	}

	if (unlikely(state_is_fetch_only(e))) {
		error = create_invalid_params_error(
			p, "fetchOnly", path);
		return error;
	}

	if (unlikely(((what == STATE) && (e->value == NULL)) ||
		((what == METHOD) && (e->value != NULL)))) {
			error =
				create_invalid_params_error(p, "set on method / call on state not possible", path);
			return error;
	}

	if (((what == STATE) && (!has_access(e->set_groups, p->set_groups))) ||
		((what == METHOD) && (!has_access(e->call_groups, p->call_groups)))) {
		error =
			create_invalid_params_error(p, "request not authorized", path);
		return error;
	}

	const cJSON *origin_request_id = cJSON_GetObjectItem(json_rpc, "id");
	if ((origin_request_id != NULL) &&
		((origin_request_id->type != cJSON_String) &&
		 (origin_request_id->type != cJSON_Number))) {
		error = create_invalid_params_error(
			p, "reason", "request id is neither string nor number");
		return error;
	}

	struct routing_request *request = alloc_routing_request(p, e->peer, origin_request_id);
	if (unlikely(request == NULL)) {
		error = create_internal_error(
			p, "reason", "could not create routing request");
		return error;
	}

	cJSON *routed_message = create_routed_message(p, path, what, value, request->id);
	if (unlikely(routed_message == NULL)) {
		error = create_internal_error(
			p, "reason", "could not create routed JSON object");
		goto routed_message_creation_failed;
	}

	error = setup_routing_information(e, timeout, request);
	if (unlikely(error != NULL)) {
		goto delete_json;
	}
	error = (cJSON *)ROUTED_MESSAGE;
	char *rendered_message = cJSON_PrintUnformatted(routed_message);
	if (unlikely(rendered_message == NULL)) {
		error = create_internal_error(p, "reason",
						  "could not render message");
		goto delete_json;
	}

	if (unlikely(e->peer->send_message(e->peer, rendered_message,
				  strlen(rendered_message)) != 0)) {
		error = create_internal_error(
			p, "reason", "could not send routing information");
	}

	cjet_free(rendered_message);
	cJSON_Delete(routed_message);
	return error;

delete_json:
	cJSON_Delete(routed_message);
routed_message_creation_failed:
	cJSON_Delete(request->origin_request_id);
	cjet_free(request);
	return error;
}

cJSON *add_state_or_method_to_peer(struct peer *p, const char *path, const cJSON *value, const cJSON *access, int flags, double routed_request_timeout_s)
{
	cJSON *error;
	struct element *e = state_table_get(path);
	if (unlikely(e != NULL)) {
		error = create_invalid_params_error(p, "exists", path);
		return error;
	}

	e = alloc_state(p);
	if (unlikely(e == NULL)) {
		error =	create_internal_error(p, "reason", "not enough memory to allocate state");
		return error;
	}

	error = init_state(e, path, value, access, p, routed_request_timeout_s, flags);
	if (unlikely(error != NULL)) {
		cjet_free(e);
		return error;
	}

	if (unlikely(find_fetchers_for_state(e) != 0)) {
		error = create_internal_error(p, "reason", "Can't notify fetching peer");
		free_state_or_method(e);
		return error;
	}

	if (unlikely(state_table_put(e->path, e) != HASHTABLE_SUCCESS)) {
		error =	create_internal_error(p, "reason", "state table full");
		free_state_or_method(e);
		return error;
	}

	list_add_tail(&e->state_list, &p->state_list);

	return NULL;
}

static void remove_state_or_method(struct element *e)
{
	notify_fetchers(e, "remove");
	list_del(&e->state_list);
	state_table_remove(e->path);
	free_state_or_method(e);
}

int remove_state_or_method_from_peer(const struct peer *p, const char *path)
{
	struct list_head *item;
	struct list_head *tmp;
	list_for_each_safe(item, tmp, &p->state_list)
	{
		struct element *e = list_entry(item, struct element, state_list);
		if (strcmp(e->path, path) == 0) {
			remove_state_or_method(e);
			return 0;
		}
	}
	return -1;
}

void remove_all_states_and_methods_from_peer(struct peer *p)
{
	struct list_head *item;
	struct list_head *tmp;
	list_for_each_safe(item, tmp, &p->state_list)
	{
		struct element *e = list_entry(item, struct element, state_list);
		remove_state_or_method(e);
	}
}
