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
#include <stdlib.h>
#include <string.h>

#include "compiler.h"
#include "fetch.h"
#include "jet_string.h"
#include "json/cJSON.h"
#include "linux/linux_io.h"
#include "list.h"
#include "log.h"
#include "peer.h"
#include "response.h"
#include "state.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define MAX(a,b) (((a)>(b))?(a):(b))

static const char case_insensitive[] = "caseInsensitive";

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

static int is_case_insensitive(const cJSON *path)
{
	const cJSON *match_ignore_case = cJSON_GetObjectItem(path, case_insensitive);
	if ((match_ignore_case != NULL) && (match_ignore_case->type == cJSON_True)) {
		return 1;
	} else {
		return 0;
	}
}

static int equals_match(const struct path_matcher *pm, const char *state_path)
{
	return !strcmp(pm->path_elements[0], state_path);
}

static int equals_match_ignore_case(const struct path_matcher *pm, const char *state_path)
{
	return !jet_strcasecmp(pm->path_elements[0], state_path);
}

static int contains_match(const struct path_matcher *pm,
	const char *state_path)
{
	return strstr(state_path, pm->path_elements[0]) != NULL;
}

static int contains_match_ignore_case(const struct path_matcher *pm,
	const char *state_path)
{
	return jet_strcasestr(state_path, pm->path_elements[0]) != NULL;
}

static int startswith_match(const struct path_matcher *pm,
	const char *state_path)
{
	size_t length = pm->cookie;
	return !strncmp(pm->path_elements[0], state_path, length);
}

static int startswith_match_ignore_case(const struct path_matcher *pm,
	const char *state_path)
{
	return !jet_strcasecmp(pm->path_elements[0], state_path);
}

static int endswith_match(const struct path_matcher *pm,
	const char *state_path)
{
	size_t fetch_path_length = strlen(pm->path_elements[0]);
	size_t state_path_length = strlen(state_path);
	return (state_path_length >= fetch_path_length) &&
		(strcmp(state_path + state_path_length - fetch_path_length, pm->path_elements[0]) == 0);
}

static int endswith_match_ignore_case(const struct path_matcher *pm,
	const char *state_path)
{
	size_t fetch_path_length = strlen(pm->path_elements[0]);
	size_t state_path_length = strlen(state_path);
	return (state_path_length >= fetch_path_length) &&
		(jet_strcasecmp(state_path + state_path_length - fetch_path_length, pm->path_elements[0]) == 0);
}

static int equalsnot_match(const struct path_matcher *pm, const char *state_path)
{
	return strcmp(pm->path_elements[0], state_path);
}

static int equalsnot_match_ignore_case(const struct path_matcher *pm, const char *state_path)
{
	return jet_strcasecmp(pm->path_elements[0], state_path);
}

static struct path_matcher *create_path_matcher(unsigned int number_of_path_elements)
{
	struct path_matcher *pm = calloc(1, sizeof(*pm) + (sizeof(pm->path_elements) * (number_of_path_elements - 1)));
	if (unlikely(pm == NULL)) {
		log_err("Could not create path matcher!\n");
	} else {
		pm->number_of_path_elements = number_of_path_elements;
	}
	return pm;
}

static void free_path_elements(const struct path_matcher *pm)
{
	for (unsigned int i; i < pm->number_of_path_elements; i++) {
		if (pm->path_elements[i] != NULL) {
			free(pm->path_elements[i]);
		}
	}
}

static int fill_path_elements(struct path_matcher *pm, const cJSON *matcher, unsigned int number_of_path_elements)
{
	if (number_of_path_elements == 1) {
		pm->path_elements[0] = duplicate_string(matcher->valuestring);
		if (unlikely(pm->path_elements[0] == NULL)) {
			return -1;
		}  
		return 0;
	} 

	const cJSON *element = matcher->child;
	for (unsigned i = 0; i < number_of_path_elements; i++) {
		if (element->type != cJSON_String) {
			goto error;
		}
		pm->path_elements[i] = duplicate_string(matcher->valuestring);
		if (unlikely(pm->path_elements[i] == NULL)) {
			goto error;
		}
		element = element->next;
	}
	return 0;

error:
	free_path_elements(pm);
	return -1;
}

static int create_matcher(struct fetch *f, const cJSON *matcher, unsigned int index, bool ignore_case)
{
	bool has_multiple_path_elements;
	unsigned int number_of_path_elements;
	match_func match_function = NULL;
	
	if (strcmp(matcher->string, "equals") == 0) {
		if (ignore_case) {
			match_function = equals_match_ignore_case;
		} else {
			match_function = equals_match;
		}
		has_multiple_path_elements = false;
	} else if (strcmp(matcher->string, "contains") == 0) {
		if (ignore_case) {
			match_function = contains_match_ignore_case;
		} else {
			match_function = contains_match;
		}
		has_multiple_path_elements = false;
	} else if (strcmp(matcher->string, "startsWith") == 0) {
		if (ignore_case) {
			match_function = startswith_match_ignore_case;
		} else {
			match_function = startswith_match;
		}
	} else if (strcmp(matcher->string, "endsWith") == 0) {
		if (ignore_case) {
			match_function = endswith_match_ignore_case;
		} else {
			match_function = endswith_match;
		}
	} else if (strcmp(matcher->string, "equalsNot") == 0) {
		if (ignore_case) {
			match_function = equalsnot_match_ignore_case;
		} else {
			match_function = equalsnot_match;
		}
	} else {
		return -1;
	}

	if (has_multiple_path_elements) {
		if (matcher->type != cJSON_Array) {
			log_err("No multiple path elements!\n");
			return -1;
		}
		number_of_path_elements = cJSON_GetArraySize(matcher);
	} else {
		if (matcher->type != cJSON_String) {
			log_err("Single path element is not a string!\n");
			return -1;
		}
		number_of_path_elements = 1;
	}

	if (unlikely(match_function == NULL)) {
		log_err("No suitable matcher found!\n");
		return -1;
	}
	struct path_matcher *pm = create_path_matcher(number_of_path_elements);
	if (unlikely(pm == NULL)) {
		return -1;
	}
	if (unlikely(fill_path_elements(pm, matcher, number_of_path_elements))) {
		free(pm);
		return -1;
	}
	pm->match_function = match_function;
	f->matcher[index] = pm;
	return 0;
}

static void free_matcher(struct fetch *f)
{
	for (unsigned int i = 0; i < f->number_of_matchers; i++) {
		if (f->matcher[i] != NULL) {
			free_path_elements(f->matcher[i]);
			free(f->matcher[i]);
		}
	}
}

static int add_matchers(struct fetch *f, const cJSON *path, bool ignore_case)
{
	unsigned int index = 0;
	const cJSON *matcher = path->child;
	while (matcher) {
		if (strncmp(matcher->string, case_insensitive, sizeof(case_insensitive)) != 0) {
			if (unlikely(create_matcher(f, matcher, index, ignore_case) < 0)) {
				goto error;
			}
		}
		index++;
		matcher = matcher->next;
	}
	return 0;
error:
	free_matcher(f);
	return -1;
}

static struct fetch *alloc_fetch(struct peer *p, const cJSON *id, unsigned int number_of_matchers)
{
	struct fetch *f;
	size_t matcher_size = sizeof(f->matcher);

	f = calloc(1, sizeof(*f) + (matcher_size * (number_of_matchers - 1)));
	if (unlikely(f == NULL)) {
		log_peer_err(p, "Could not allocate memory for %s object!\n", "fetch");
		return NULL;
	}
	INIT_LIST_HEAD(&f->next_fetch);
	f->peer = p;
	f->number_of_matchers = number_of_matchers;
	f->fetch_id = cJSON_Duplicate(id, 1);
	if (unlikely(f->fetch_id == NULL)) {
		log_peer_err(p, "Could not allocate memory for %s object!\n", "fetch ID");
		free(f);
		return NULL;
	}
	return f;
}

static struct fetch *create_fetch(struct peer *p, const cJSON *id, const cJSON *params)
{
	const cJSON *path = cJSON_GetObjectItem(params, "path");
	if (path == NULL) {
		return alloc_fetch(p, id, 1);
	}
	if (unlikely(path->type != cJSON_Object)) {
		log_peer_err(p, "Fetch path is not an object!\n");
		return NULL;
	}

	unsigned int number_of_matchers = cJSON_GetArraySize(path);
	int ignore_case = is_case_insensitive(path);
	if (ignore_case) {
		number_of_matchers--;
	}
	if (unlikely(number_of_matchers == 0)) {
		log_peer_err(p, "No matcher in path object\n");
		return NULL;
	}
	if (unlikely(number_of_matchers > 12)) {
		log_peer_err(p, "Too many matchers in path object\n");
		return NULL;
	}

	struct fetch *f = alloc_fetch(p, id, number_of_matchers);
	if (unlikely(f == NULL)) {
		return NULL;
	}

	if (unlikely(add_matchers(f, path, ignore_case) < 0)) {
		log_peer_err(p, "Could not add matchers to fetch!\n");
		cJSON_Delete(f->fetch_id);
		free(f);
		return NULL;
	}

	return f;
}

static void free_fetch(struct fetch *f)
{
	free_matcher(f);
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

static int state_matches(struct state_or_method *s, struct fetch *f)
{
	if (f->matcher[0] == NULL) {
		/*
		 * no match function given, so it was a fetch all
		 * command
		 */
		 return 1;
	}

	unsigned int match_array_size = ARRAY_SIZE(f->matcher);
	for (unsigned int i = 0; i < match_array_size; ++i) {
		if (f->matcher[i]->match_function != NULL) {
			int ret = f->matcher[i]->match_function((f->matcher[i]), s->path);
			if (ret == 0) {
				return 0;
			}
		}
	}
	return 1;
}

static int add_fetch_to_state(struct state_or_method *s, struct fetch *f)
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

static int notify_fetching_peer(struct state_or_method *s, struct fetch *f,
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

	if (state_is_fetch_only(s)) {
		cJSON_AddTrueToObject(param, "fetchOnly");
	}

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

	if (s->value != NULL) {
		cJSON *value = cJSON_Duplicate(s->value, 1);
		if (unlikely(value == NULL)) {
			cJSON_Delete(root);
			return -1;
		}
		cJSON_AddItemToObject(param, "value", value);
	}

	char *rendered_message = cJSON_PrintUnformatted(root);
	if (unlikely(rendered_message == NULL)) {
		cJSON_Delete(root);
		return -1;
	}
	struct peer *p = f->peer;
	if (unlikely(p->send_message(p, rendered_message,
			strlen(rendered_message)) != 0)) {
		cJSON_Delete(root);
		free(rendered_message);
		return -1;
	}

	cJSON_Delete(root);
	free(rendered_message);

	return 0;
}

static int add_fetch_to_state_and_notify(const struct peer *p, struct state_or_method *s, struct fetch *f)
{
	if (state_matches(s, f)) {
		if (unlikely(add_fetch_to_state(s, f) != 0)) {
			log_peer_err(p, "Can't add fetch to state %s owned by %s", s->path, get_peer_name(s->peer));
			return -1;
		}
		if (unlikely(notify_fetching_peer(s, f, "add") != 0)) {
			log_peer_err(p, "Can't notify fetching peer for state %s owned by %s", s->path, get_peer_name(s->peer));
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
		struct state_or_method *s = list_entry(item, struct state_or_method, state_list);
		if (unlikely(add_fetch_to_state_and_notify(p, s, f) != 0)) {
			return -1;
		}
	}
	return 0;
}

int notify_fetchers(struct state_or_method *s, const char *event_name)
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
			return create_internal_error(p, "reason", "could not add fetch to state");
		}
	}
	return NULL;
}

static void remove_fetch_from_state(struct state_or_method *s, struct fetch *f)
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
		struct state_or_method *s = list_entry(item, struct state_or_method, state_list);
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
	struct state_or_method *s) {

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

int find_fetchers_for_state(struct state_or_method *s)
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
	const cJSON *matches = cJSON_GetObjectItem(params, "match");
	if (unlikely(matches != NULL)) {
		static const char deprecated[] = "No support for deprecated match";
		error = create_invalid_params_error(p, "reason", deprecated);
		log_peer_err(p, deprecated);
		return error;
	}

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

	f = create_fetch(p, id, params);
	if (unlikely(f == NULL)) {
		error = create_internal_error(p, "reason", "not enough memory");
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
