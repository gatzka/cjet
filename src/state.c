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

static bool is_state(const struct state_or_method *s)
{
	return (s->value != NULL);
}

static void free_fetch_groups(struct state_or_method *s, unsigned int elements)
{
	for (unsigned int i = 0; i < elements; i++) {
		cjet_free(s->fetchGroups[i]);
	}

	cjet_free(s->fetchGroups);
}

static int fill_fetch_groups(struct state_or_method *s, const cJSON *access)
{
	const cJSON *fetchGroups = cJSON_GetObjectItem(access, "fetchGroups");
	if ((fetchGroups != NULL) && (fetchGroups->type != cJSON_Array)) {
		return -1;
	}

	unsigned int number_of_fetch_groups = cJSON_GetArraySize(fetchGroups);
	if (number_of_fetch_groups != 0) {
		s->fetchGroups = cjet_malloc(sizeof(*(s->fetchGroups)) * number_of_fetch_groups);
		if (s->fetchGroups == NULL) {
			return -1;
		}

		for (unsigned int i = 0; i < number_of_fetch_groups; i++) {
			cJSON *fetchGroup = cJSON_GetArrayItem(fetchGroups, i);
			if ((fetchGroup == NULL) || (fetchGroup->type != cJSON_String)) {
				if (i > 0) {
					free_fetch_groups(s, i - 1);
				}
				return -1;
			}
			s->fetchGroups[i] = duplicate_string(fetchGroup->valuestring);
			if (s->fetchGroups[i] == NULL) {
				if (i > 0) {
					free_fetch_groups(s, i - 1);
				}
				return -1;
			}
		}
	}

	return 0;
}

static int fill_access(struct state_or_method *s, const cJSON *access)
{
	int ret = fill_fetch_groups(s, access);
	if (ret < 0) {
		return -1;
	}
	if (is_state(s)) {
		// check for fetchGroups or setGroups
	} else {
		// check for fetchGroups or callGroups
	}
	return 0;
}

static struct state_or_method *alloc_state(const char *path, const cJSON *value_object, const cJSON *access,
				 struct peer *p, double timeout, int flags)
{
	struct state_or_method *s = cjet_calloc(1, sizeof(*s));
	if (unlikely(s == NULL)) {
		log_peer_err(p, "Could not allocate memory for %s object!\n",
				 "state");
		return NULL;
	}

	s->flags = flags;
	s->timeout = timeout;
	s->fetch_table_size = CONFIG_INITIAL_FETCH_TABLE_SIZE;
	s->fetcher_table = cjet_calloc(s->fetch_table_size, sizeof(struct fetch *));
	if (s->fetcher_table == NULL) {
		log_peer_err(p, "Could not allocate memory for fetch table!\n");
		goto alloc_fetch_table_failed;
	}

	s->path = duplicate_string(path);
	if (unlikely(s->path == NULL)) {
		log_peer_err(p, "Could not allocate memory for %s object!\n",
				 "path");
		goto alloc_path_failed;
	}
	if (value_object != NULL) {
		cJSON *value_copy = cJSON_Duplicate(value_object, 1);
		if (unlikely(value_copy == NULL)) {
			log_peer_err(p, "Could not copy value object!\n");
			goto value_copy_failed;
		}
		s->value = value_copy;
	}
	INIT_LIST_HEAD(&s->state_list);
	s->peer = p;

	if (fill_access(s, access) < 0) {
		log_peer_err(p, "Could not fill access information!\n");
		goto fill_access_failed;
	}

	return s;

fill_access_failed:
	if (s->value != NULL) {
		cJSON_Delete(s->value);
	}
value_copy_failed:
	cjet_free(s->path);
alloc_path_failed:
	cjet_free(s->fetcher_table);
alloc_fetch_table_failed:
	cjet_free(s);
	return NULL;
}

static void free_state_or_method(struct state_or_method *s)
{
	if (s->value != NULL) {
		cJSON_Delete(s->value);
	}

	free_fetch_groups(s, s->number_of_fetch_groups);
	cjet_free(s->path);
	cjet_free(s->fetcher_table);
	cjet_free(s);
}

bool state_is_fetch_only(struct state_or_method *s)
{
	if ((s->flags & FETCH_ONLY_FLAG) == FETCH_ONLY_FLAG) {
		return true;
	} else {
		return false;
	}
}

cJSON *change_state(const struct peer *p, const char *path, const cJSON *value)
{
	struct state_or_method *s = state_table_get(path);
	if (unlikely(s == NULL)) {
		cJSON *error =
			create_invalid_params_error(p, "not exists", path);
		return error;
	}
	if (unlikely(s->peer != p)) {
		cJSON *error =
			create_invalid_params_error(p, "not owner of state", path);
		return error;
	}
	if (unlikely(s->value == NULL)) {
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
	cJSON_Delete(s->value);
	s->value = value_copy;
	if (unlikely(notify_fetchers(s, "change") != 0)) {
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
	struct state_or_method *s = state_table_get(path);
	if (unlikely(s == NULL)) {
		error = create_invalid_params_error(p, "not exists", path);
		return error;
	}

	if (unlikely(state_is_fetch_only(s))) {
		error = create_invalid_params_error(
			p, "fetchOnly", path);
		return error;
	}

	if (unlikely(((what == STATE) && (s->value == NULL)) ||
		((what == METHOD) && (s->value != NULL)))) {
			error =
				create_invalid_params_error(p, "set on method / call on state not possible", path);
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

	struct routing_request *request = alloc_routing_request(p, s->peer, origin_request_id);
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

	error = setup_routing_information(s, timeout, request);
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

	if (unlikely(s->peer->send_message(s->peer, rendered_message,
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
	struct state_or_method *s = state_table_get(path);
	if (unlikely(s != NULL)) {
		cJSON *error = create_invalid_params_error(p, "exists", path);
		return error;
	}
	s = alloc_state(path, value, access, p, routed_request_timeout_s, flags);
	if (unlikely(s == NULL)) {
		cJSON *error =
			create_internal_error(p, "reason", "not enough memory");
		return error;
	}

	if (unlikely(find_fetchers_for_state(s) != 0)) {
		cJSON *error = create_internal_error(
			p, "reason", "Can't notify fetching peer");
		free_state_or_method(s);
		return error;
	}

	if (unlikely(state_table_put(s->path, s) != HASHTABLE_SUCCESS)) {
		cJSON *error =
			create_internal_error(p, "reason", "state table full");
		free_state_or_method(s);
		return error;
	}

	list_add_tail(&s->state_list, &p->state_list);

	return NULL;
}

static void remove_state_or_method(struct state_or_method *s)
{
	notify_fetchers(s, "remove");
	list_del(&s->state_list);
	state_table_remove(s->path);
	free_state_or_method(s);
}

int remove_state_or_method_from_peer(const struct peer *p, const char *path)
{
	struct list_head *item;
	struct list_head *tmp;
	list_for_each_safe(item, tmp, &p->state_list)
	{
		struct state_or_method *s = list_entry(item, struct state_or_method, state_list);
		if (strcmp(s->path, path) == 0) {
			remove_state_or_method(s);
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
		struct state_or_method *s = list_entry(item, struct state_or_method, state_list);
		remove_state_or_method(s);
	}
}
