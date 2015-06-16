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


#include <stdlib.h>
#include <string.h>

#include "compiler.h"
#include "config/io.h"
#include "fetch.h"
#include "jet_string.h"
#include "json/cJSON.h"
#include "peer.h"
#include "response.h"
#include "state.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define MAX(a,b) (((a)>(b))?(a):(b))

static const cJSON *get_fetch_id(const struct peer *p, const cJSON *params, cJSON **err)
{
	const cJSON *id = cJSON_GetObjectItem(params, "id");
	if (unlikely(id == NULL)) {
		*err =
			 create_invalid_params_error(p, "reason", "no fetch id given");
		return NULL;
	}
	if (unlikely((id->type != cJSON_String) && (id->type != cJSON_Number))) {
		*err = create_invalid_params_error(p, "reason",
			"fetch ID is neither a string nor a number");
		return NULL;
	}
	*err = NULL;
	return id;
}

static struct fetch *alloc_fetch(struct peer *p, const cJSON *id)
{
	struct fetch *f = calloc(1, sizeof(*f));
	if (unlikely(f == NULL)) {
		log_peer_err(p, "Could not allocate memory for %s object!\n", "fetch");
		return NULL;
	}
	INIT_LIST_HEAD(&f->next_fetch);
	f->peer = p;
	f->fetch_id = cJSON_Duplicate(id, 1);
	if (unlikely(f->fetch_id == NULL)) {
		log_peer_err(p, "Could not allocate memory for %s object!\n", "fetch ID");
		free(f);
		return NULL;
	}

	return f;
}

static void remove_matchers(struct fetch *f)
{
	struct path_matcher *path_matcher = f->matcher;
	while (path_matcher->fetch_path != NULL) {
		free(path_matcher->fetch_path);
		++path_matcher;
	}
}

static void free_fetch(struct fetch *f)
{
	remove_matchers(f);
	cJSON_Delete(f->fetch_id);
	free(f);
}

static int ids_equal(const cJSON *id1, const cJSON *id2)
{
	if (id1->type != id2->type) {
		return 0;
	}
	if ((id1->type == cJSON_Number) && (id1->valueint == id2->valueint)) {
		return 1;
	}
	if ((id1->type == cJSON_String) && (strcmp(id1->valuestring, id2->valuestring) == 0)) {
		return 1;
	}
	return 0;
}

static struct fetch *find_fetch(const struct peer *p, const cJSON *id)
{
	struct list_head *item;
	struct list_head *tmp;
	list_for_each_safe(item, tmp, &p->fetch_list) {
		struct fetch *f = list_entry(item, struct fetch, next_fetch);
		if (ids_equal(f->fetch_id, id)) {
			return f;
		}
	}
	return NULL;
}

static int equals_match(const struct path_matcher *pm, const char *state_path)
{
	return !strcmp(pm->fetch_path, state_path);
}

static int equals_match_ignore_case(const struct path_matcher *pm, const char *state_path)
{
	return !strcasecmp(pm->fetch_path, state_path);
}

static int equalsnot_match(const struct path_matcher *pm, const char *state_path)
{
	return strcmp(pm->fetch_path, state_path);
}

static int equalsnot_match_ignore_case(const struct path_matcher *pm, const char *state_path)
{
	return strcasecmp(pm->fetch_path, state_path);
}

static int startswith_match(const struct path_matcher *pm,
	const char *state_path)
{
	size_t length = pm->cookie;
	return !strncmp(pm->fetch_path, state_path, length);
}

static int startswith_match_ignore_case(const struct path_matcher *pm,
	const char *state_path)
{
	size_t length = pm->cookie;
	return !strncasecmp(pm->fetch_path, state_path, length);
}

static int endswith_match(const struct path_matcher *pm,
	const char *state_path)
{
	size_t fetch_path_length = pm->cookie;
	size_t state_path_length = strlen(state_path);
	return (state_path_length >= fetch_path_length) &&
		(strcmp(state_path + state_path_length - fetch_path_length, pm->fetch_path) == 0);
}

static int endswith_match_ignore_case(const struct path_matcher *pm,
	const char *state_path)
{
	size_t fetch_path_length = pm->cookie;
	size_t state_path_length = strlen(state_path);
	return (state_path_length >= fetch_path_length) &&
		(strcasecmp(state_path + state_path_length - fetch_path_length, pm->fetch_path) == 0);
}

static int contains_match(const struct path_matcher *pm,
	const char *state_path)
{
	return strstr(state_path, pm->fetch_path) != NULL;
}

static int contains_match_ignore_case(const struct path_matcher *pm,
	const char *state_path)
{
	return jet_strcasestr(state_path, pm->fetch_path) != NULL;
}

static int get_match_function(struct path_matcher *pm, const char *path,
	const char *fetch_type, int ignore_case)
{
	if (strcmp(fetch_type, "equals") == 0) {
		if (ignore_case) {
			pm->match_function = equals_match_ignore_case;
		} else {
			pm->match_function = equals_match;
		}
		return 0;
	}
	if (strcmp(fetch_type, "startsWith") == 0) {
		if (ignore_case) {
			pm->match_function = startswith_match_ignore_case;
		} else {
			pm->match_function = startswith_match;
		}
		pm->cookie = strlen(path);
		return 0;
	}
	if (strcmp(fetch_type, "endsWith") == 0) {
		if (ignore_case) {
			pm->match_function = endswith_match_ignore_case;
		} else {
			pm->match_function = endswith_match;
		}
		pm->cookie = strlen(path);
		return 0;
	}
	if (strcmp(fetch_type, "contains") == 0) {
		if (ignore_case) {
			pm->match_function = contains_match_ignore_case;
		} else {
			pm->match_function = contains_match;
		}
		return 0;
	}
	if (strcmp(fetch_type, "equalsNot") == 0) {
		if (ignore_case) {
			pm->match_function = equalsnot_match_ignore_case;
		} else {
			pm->match_function = equalsnot_match;
		}
		return 0;
	}
	return -1;
}

static cJSON *fill_matcher(const struct peer *p, struct path_matcher *matcher,
	const char *fetch_type, int ignore_case, const char *path)
{
	if (unlikely(get_match_function(matcher, path, fetch_type, ignore_case) < 0)) {
		return create_internal_error(p, "reason",
			"match function not implemented");
	}
	matcher->fetch_path = duplicate_string(path);
	if (unlikely(matcher->fetch_path == NULL)) {
		return create_internal_error(p, "reason", "not enough memory");
	}

	return NULL;
}

static int is_case_insensitive(const cJSON *params)
{
	const cJSON *match_ignore_case = cJSON_GetObjectItem(params, "caseInsensitive");
	if ((match_ignore_case != NULL) && (match_ignore_case->type == cJSON_True)) {
		return 1;
	} else {
		return 0;
	}
}

static cJSON *add_path_matchers(const struct peer *p, struct fetch *f, const cJSON *params)
{
	const cJSON *path = cJSON_GetObjectItem(params, "path");
	if (path == NULL) {
		return NULL;
	}
	if (unlikely(path->type != cJSON_Object)) {
		return create_invalid_params_error(
			p, "reason", "fetch path is not an object");
	}

	int ignore_case = is_case_insensitive(params);

	const cJSON *matcher = path->child;
	struct path_matcher *path_matcher = f->matcher;
	while (matcher) {
		if (unlikely(matcher->type != cJSON_String)) {
			return create_invalid_params_error(
				p, "reason", "match path is not a string");
		}
		cJSON *error = fill_matcher(p, path_matcher, matcher->string, ignore_case,
			matcher->valuestring);
		if (unlikely(error != NULL)) {
			return error;
		}
		matcher = matcher->next;
		++path_matcher;
	}
	return NULL;
}

static cJSON *add_matchers(const struct peer *p, struct fetch *f, const cJSON *params)
{
	cJSON *error = add_path_matchers(p, f, params);
	if (unlikely(error != NULL)) {
		return error;
	}
	return NULL;
}

static int state_matches(struct state *s, struct fetch *f)
{
	if (f->matcher[0].match_function == NULL) {
		/*
		 * no match function given, so it was a fetch all
		 * command
		 */
		 return 1;
	}

	unsigned int match_array_size = ARRAY_SIZE(f->matcher);
	for (unsigned int i = 0; i < match_array_size; ++i) {
		if (f->matcher[i].match_function != NULL) {
			int ret = f->matcher[i].match_function(&(f->matcher[i]), s->path);
			if (ret == 0) {
				return 0;
			}
		}
	}
	return 1;
}

static int add_fetch_to_state(struct state *s, struct fetch *f)
{
	for (unsigned int i = 0; i < s->fetch_table_size; i++) {
		if (s->fetcher_table[i] == NULL) {
			s->fetcher_table[i] = f;
			return 0;
		}
	}
	unsigned int new_size = MAX(CONFIG_INITIAL_FETCH_TABLE_SIZE, s->fetch_table_size * 2);
	void *new_fetch_table = calloc(new_size, sizeof(struct fetch*));
	if (new_fetch_table == NULL) {
		return -1;
	}
	memcpy(new_fetch_table, s->fetcher_table, s->fetch_table_size * sizeof(struct fetch*));
	s->fetch_table_size = new_size;
	free(s->fetcher_table);
	s->fetcher_table = new_fetch_table;
	return add_fetch_to_state(s, f);
}

static int notify_fetching_peer(struct state *s, struct fetch *f,
	const char *event_name)
{
	cJSON *root = cJSON_CreateObject();
	if (unlikely(root == NULL)) {
		return -1;
	}
	cJSON *fetch_id = cJSON_Duplicate(f->fetch_id, 1);
	if (unlikely(fetch_id == NULL)) {
		cJSON_Delete(root);
		return -1;
	}
	cJSON_AddItemToObject(root, "method", fetch_id);

	cJSON *param = cJSON_CreateObject();
	if (unlikely(param == NULL)) {
		cJSON_Delete(root);
		return -1;
	}
	cJSON_AddItemToObject(root, "params", param);

	cJSON *value = cJSON_Duplicate(s->value, 1);
	if (unlikely(value == NULL)) {
		cJSON_Delete(root);
		return -1;
	}
	cJSON_AddItemToObject(param, "value", value);

	cJSON *path = cJSON_CreateString(s->path);
	if (unlikely(path == NULL)) {
		cJSON_Delete(root);
		return -1;
	}
	cJSON_AddItemToObject(param, "path", path);

	cJSON *event = cJSON_CreateString(event_name);
	if (unlikely(event == NULL)) {
		cJSON_Delete(root);
		return -1;
	}
	cJSON_AddItemToObject(param, "event", event);

	char *rendered_message = cJSON_PrintUnformatted(root);
	if (unlikely(rendered_message == NULL)) {
		cJSON_Delete(root);
		return -1;
	}
	if (unlikely(send_message(f->peer, rendered_message,
			strlen(rendered_message)) != 0)) {
		cJSON_Delete(root);
		free(rendered_message);
		return -1;
	}

	cJSON_Delete(root);
	free(rendered_message);

	return 0;
}

static int add_fetch_to_state_and_notify(const struct peer *p, struct state *s, struct fetch *f)
{
	if (state_matches(s, f)) {
		if (unlikely(add_fetch_to_state(s, f) != 0)) {
			log_peer_err(p, "Can't add fetch to state");
			return -1;
		}
		if (unlikely(notify_fetching_peer(s, f, "add") != 0)) {
			log_peer_err(p, "Can't notify fetching peer");
			return -1;
		}
	}
	return 0;
}

static int add_fetch_to_states_in_peer(struct peer *p, struct fetch *f)
{
	struct list_head *item;
	struct list_head *tmp;
	list_for_each_safe(item, tmp, &p->state_list) {
		struct state *s = list_entry(item, struct state, state_list);
		if (unlikely(add_fetch_to_state_and_notify(p, s, f) != 0)) {
			return -1;
		}
	}
	return 0;
}

int notify_fetchers(struct state *s, const char *event_name)
{
	for (unsigned int i = 0; i < s->fetch_table_size; i++) {
		struct fetch *f = s->fetcher_table[i];
		if ((f != NULL) &&
				(unlikely(notify_fetching_peer(s, f, event_name) != 0))) {
			return -1;
		}
	}
	return 0;
}

cJSON *add_fetch_to_states(struct fetch *f)
{
	struct list_head *item;
	struct list_head *tmp;
	struct list_head *peer_list = get_peer_list();
	list_for_each_safe(item, tmp, peer_list) {
		struct peer *p = list_entry(item, struct peer, next_peer);
		int ret = add_fetch_to_states_in_peer(p, f);
		if (unlikely(ret != 0)) {
			//TODO: create error
			return NULL;
		}
	}
	return NULL;
}

static void remove_fetch_from_state(struct state *s, struct fetch *f)
{
	for (unsigned int i = 0; i < s->fetch_table_size; ++i) {
		if (s->fetcher_table[i] == f) {
			s->fetcher_table[i] = NULL;
		}
	}
}

static void rem_fetch_from_states_in_peer(struct peer *p, struct fetch *f)
{
	struct list_head *item;
	struct list_head *tmp;
	list_for_each_safe(item, tmp, &p->state_list) {
		struct state *s = list_entry(item, struct state, state_list);
		remove_fetch_from_state(s, f);
	}
}

static void remove_fetch_from_states(struct fetch *f)
{
	struct list_head *item;
	struct list_head *tmp;
	struct list_head *peer_list = get_peer_list();
	list_for_each_safe(item, tmp, peer_list) {
		struct peer *p = list_entry(item, struct peer, next_peer);
		rem_fetch_from_states_in_peer(p, f);
	}
}

static int find_fetchers_for_state_in_peer(const struct peer *p,
	struct state *s) {

	struct list_head *item;
	struct list_head *tmp;
	list_for_each_safe(item, tmp, &p->fetch_list) {
		struct fetch *f = list_entry(item, struct fetch, next_fetch);
		if (unlikely(add_fetch_to_state_and_notify(p, s, f) != 0)) {
			return -1;
		}
	}
	return 0;
}

int find_fetchers_for_state(struct state *s)
{
	int ret = 0;
	struct list_head *item;
	struct list_head *tmp;
	struct list_head *peer_list = get_peer_list();
	list_for_each_safe(item, tmp, peer_list) {
		struct peer *p = list_entry(item, struct peer, next_peer);
		ret = find_fetchers_for_state_in_peer(p, s);
		if (unlikely(ret != 0)) {
			return ret;
		}
	}
	return ret;
}

cJSON *add_fetch_to_peer(struct peer *p, const cJSON *params,
	struct fetch **fetch_return)
{
	cJSON *error;
	const cJSON *id = get_fetch_id(p, params, &error);
	if (unlikely(id == NULL)) {
		return error;
	}
	struct fetch *f = find_fetch(p, id);
	if (unlikely(f != NULL)) {
		error = create_invalid_params_error(p, "reason",
			"fetch ID already in use");
		return error;
	}

	f = alloc_fetch(p, id);
	if (unlikely(f == NULL)) {
		error = create_internal_error(p, "reason", "not enough memory");
		return error;
	}

	error = add_matchers(p, f, params);
	if (unlikely(error != NULL)) {
		free_fetch(f);
		return error;
	}

	list_add_tail(&f->next_fetch, &p->fetch_list);
	*fetch_return = f;
	return NULL;
}

cJSON *remove_fetch_from_peer(struct peer *p, const cJSON *params)
{
	cJSON *error;
	const cJSON *id = get_fetch_id(p, params, &error);
	if (unlikely(id == NULL)) {
		return error;
	}
	struct fetch *f = find_fetch(p, id);
	if (unlikely(f == NULL)) {
		error = create_invalid_params_error(p, "reason",
			"fetch ID not found for unfetch");
		return error;
	}
	remove_fetch_from_states(f);
	list_del(&f->next_fetch);
	free_fetch(f);
	return NULL;
}

void remove_all_fetchers_from_peer(struct peer *p)
{
	struct list_head *item;
	struct list_head *tmp;
	list_for_each_safe(item, tmp, &p->fetch_list) {
		struct fetch *f = list_entry(item, struct fetch, next_fetch);
		remove_fetch_from_states(f);
		list_del(&f->next_fetch);
		free_fetch(f);
	}
}
