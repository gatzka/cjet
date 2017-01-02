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
#include <string.h>

#include "alloc.h"
#include "compiler.h"
#include "fetch.h"
#include "groups.h"
#include "jet_string.h"
#include "json/cJSON.h"
#include "linux/linux_io.h"
#include "list.h"
#include "log.h"
#include "peer.h"
#include "request.h"
#include "response.h"

#define MAX(a,b) (((a)>(b))?(a):(b))

#ifndef ARRAY_SIZE
# define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

static const char case_insensitive[] = "caseInsensitive";

struct supported_matcher {
	const char *matcher_name;
	match_func case_sensitive;
	match_func case_insensitive;
	bool has_multiple_path_elements;
};

static const cJSON *get_fetch_id(const struct peer *p, const cJSON *request, const cJSON *params, cJSON **response)
{
	const cJSON *id = cJSON_GetObjectItem(params, "id");
	if (unlikely(id == NULL)) {
		*response = create_error_response_from_request(p, request, INVALID_PARAMS, "reason", "no fetch id given");
		return NULL;
	}
	if (unlikely((id->type != cJSON_String) && (id->type != cJSON_Number))) {
		*response = create_error_response_from_request(p, request, INVALID_PARAMS, "reason", "fetch id is neither string nor number");
		return NULL;
	}
	*response = NULL;
	return id;
}

static const cJSON *get_case_insensitive(const cJSON *path)
{
	return cJSON_GetObjectItem(path, case_insensitive);
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
	size_t fetch_path_length = strlen(pm->path_elements[0]);
	return !strncmp(pm->path_elements[0], state_path, fetch_path_length);
}

static int startswith_match_ignore_case(const struct path_matcher *pm,
	const char *state_path)
{
	size_t fetch_path_length = strlen(pm->path_elements[0]);
	return !jet_strncasecmp(pm->path_elements[0], state_path, fetch_path_length);
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

static int containsallof_match(const struct path_matcher *pm, const char *state_path)
{
	for (unsigned int i = 0; i < pm->number_of_path_elements; i++) {
		if (strstr(state_path, pm->path_elements[i]) == NULL) {
			return 0;
		}
	}
	return 1;
}

static int containsallof_match_ignore_case(const struct path_matcher *pm, const char *state_path)
{
	for (unsigned int i = 0; i < pm->number_of_path_elements; i++) {
		if (jet_strcasestr(state_path, pm->path_elements[i]) == NULL) {
			return 0;
		}
	}
	return 1;
}

static const struct supported_matcher matchers[] = {
	{.matcher_name = "equals", .case_sensitive = equals_match, .case_insensitive = equals_match_ignore_case, .has_multiple_path_elements = false},
	{.matcher_name = "contains", .case_sensitive = contains_match, .case_insensitive = contains_match_ignore_case, .has_multiple_path_elements = false},
	{.matcher_name = "startsWith", .case_sensitive = startswith_match, .case_insensitive = startswith_match_ignore_case, .has_multiple_path_elements = false},
	{.matcher_name = "endsWith", .case_sensitive = endswith_match, .case_insensitive = endswith_match_ignore_case,.has_multiple_path_elements = false},
	{.matcher_name = "equalsNot", .case_sensitive = equalsnot_match, .case_insensitive = equalsnot_match_ignore_case,.has_multiple_path_elements = false},
	{.matcher_name = "containsAllOf", .case_sensitive = containsallof_match, .case_insensitive = containsallof_match_ignore_case, .has_multiple_path_elements = true}
};

static struct path_matcher *create_path_matcher(unsigned int number_of_path_elements)
{
	struct path_matcher *pm = cjet_calloc(1, sizeof(*pm) + (sizeof(pm->path_elements) * (number_of_path_elements - 1)));
	if (unlikely(pm == NULL)) {
		log_err("Could not create path matcher!\n");
	} else {
		pm->number_of_path_elements = number_of_path_elements;
	}
	return pm;
}

static void free_path_elements(const struct path_matcher *pm)
{
	for (unsigned int i = 0; i < pm->number_of_path_elements; i++) {
		if (pm->path_elements[i] != NULL) {
			cjet_free(pm->path_elements[i]);
		}
	}
}

static int fill_path_elements(struct path_matcher *pm, const cJSON *matcher, bool has_multiple_path_elements, unsigned int number_of_path_elements)
{
	if (!has_multiple_path_elements) {
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
		pm->path_elements[i] = duplicate_string(element->valuestring);
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

static int create_matcher(struct fetch *f, const cJSON *matcher, unsigned int match_index, bool ignore_case)
{

	for (unsigned int i = 0; i < ARRAY_SIZE(matchers); i++) {
		if (strcmp(matcher->string, matchers[i].matcher_name) == 0) {
			match_func match_function;
			if (ignore_case) {
				match_function = matchers[i].case_insensitive;
			} else {
				match_function = matchers[i].case_sensitive;
			}
			bool has_multiple_path_elements = matchers[i].has_multiple_path_elements;

			unsigned int number_of_path_elements;
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
			if (unlikely(fill_path_elements(pm, matcher, has_multiple_path_elements, number_of_path_elements))) {
				cjet_free(pm);
				return -1;
			}
			pm->match_function = match_function;
			f->matcher[match_index] = pm;
			return 0;
		}
	}
	return -1;
}

static void free_matcher(struct fetch *f)
{
	for (unsigned int i = 0; i < f->number_of_matchers; i++) {
		if (f->matcher[i] != NULL) {
			free_path_elements(f->matcher[i]);
			cjet_free(f->matcher[i]);
		}
	}
}

static int add_matchers(struct fetch *f, const cJSON *path, bool ignore_case)
{
	unsigned int match_index = 0;
	const cJSON *matcher = path->child;
	while (matcher) {
		if (strncmp(matcher->string, case_insensitive, sizeof(case_insensitive)) != 0) {
			if (unlikely(create_matcher(f, matcher, match_index, ignore_case) < 0)) {
				goto error;
			}
		}
		match_index++;
		matcher = matcher->next;
	}
	return 0;
error:
	free_matcher(f);
	return -1;
}

static struct fetch *alloc_fetch(const struct peer *p, const cJSON *id, unsigned int number_of_matchers)
{
	struct fetch *f;
	size_t matcher_size = sizeof(f->matcher);

	f = cjet_calloc(1, sizeof(*f) + (matcher_size * (number_of_matchers - 1)));
	if (unlikely(f == NULL)) {
		log_peer_err(p, "Could not allocate memory for %s object!\n", "fetch");
		return NULL;
	}
	INIT_LIST_HEAD(&f->next_fetch);
	f->peer = p;
	f->number_of_matchers = number_of_matchers;
	if (id != NULL) {
		f->fetch_id = cJSON_Duplicate(id, 1);
		if (unlikely(f->fetch_id == NULL)) {
			log_peer_err(p, "Could not allocate memory for %s object!\n", "fetch ID");
			cjet_free(f);
			return NULL;
		}
	}
	return f;
}

static struct fetch *create_fetch(const struct peer *p, const cJSON *request, const cJSON *id, const cJSON *params, cJSON **response)
{
	const cJSON *path = cJSON_GetObjectItem(params, "path");
	if (path == NULL) {
		return alloc_fetch(p, id, 1);
	}

	if (unlikely(path->type != cJSON_Object)) {
		*response = create_error_response_from_request(p, request, INVALID_PARAMS, "reason", "fetch path is not an object");
		return NULL;
	}

	unsigned int number_of_matchers = cJSON_GetArraySize(path);

	int ignore_case;
	const cJSON *match_ignore_case = get_case_insensitive(path);
	if (match_ignore_case != NULL) {
		number_of_matchers--;
		if (match_ignore_case->type == cJSON_True) {
			ignore_case = 1;
		} else {
			ignore_case = 0;
		}
	} else {
		ignore_case = 0;
	}

	if (unlikely(number_of_matchers == 0)) {
		*response = create_error_response_from_request(p, request, INVALID_PARAMS, "reason", "no matcher in path object");
		return NULL;
	}
	if (unlikely(number_of_matchers > CONFIG_MAX_NUMBERS_OF_MATCHERS_IN_FETCH)) {
		*response = create_error_response_from_request(p, request, INVALID_PARAMS, "reason", "too many matchers in path object");
		return NULL;
	}

	struct fetch *f = alloc_fetch(p, id, number_of_matchers);
	if (unlikely(f == NULL)) {
		*response = create_error_response_from_request(p, request, INTERNAL_ERROR, "reason", "not enough memory to allocate fetch");
		return NULL;
	}

	if (unlikely(add_matchers(f, path, ignore_case) < 0)) {
		*response = create_error_response_from_request(p, request, INTERNAL_ERROR, "reason", "could not add matchers to fetch");
		cJSON_Delete(f->fetch_id);
		cjet_free(f);
		return NULL;
	}

	return f;
}

static void free_fetch(struct fetch *f)
{
	free_matcher(f);
	cJSON_Delete(f->fetch_id);
	cjet_free(f);
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

static int state_matches(const struct element *e, const struct fetch *f)
{
	if (f->matcher[0] == NULL) {
		/*
		 * no match function given, so it was a fetch all
		 * command
		 */
		 return 1;
	}

	unsigned int match_array_size = f->number_of_matchers;
	for (unsigned int i = 0; i < match_array_size; ++i) {
		const struct path_matcher *pm = f->matcher[i];
		int ret = pm->match_function(pm, e->path);
		if (ret == 0) {
			return 0;
		}
	}
	return 1;
}

static int add_fetch_to_state(struct element *e, const struct fetch *f)
{
	for (unsigned int i = 0; i < e->fetch_table_size; i++) {
		if (e->fetcher_table[i] == NULL) {
			e->fetcher_table[i] = f;
			return 0;
		}
	}
	unsigned int new_size = MAX(CONFIG_INITIAL_FETCH_TABLE_SIZE, e->fetch_table_size * 2);
	void *new_fetch_table = cjet_calloc(new_size, sizeof(struct fetch*));
	if (new_fetch_table == NULL) {
		return -1;
	}
	memcpy(new_fetch_table, e->fetcher_table, e->fetch_table_size * sizeof(struct fetch*));
	e->fetch_table_size = new_size;
	cjet_free(e->fetcher_table);
	e->fetcher_table = new_fetch_table;
	return add_fetch_to_state(e, f);
}

static int notify_fetching_peer(const struct element *e, const struct fetch *f,
	const char *event_name)
{
	cJSON *root = cJSON_CreateObject();
	if (unlikely(root == NULL)) {
		return -1;
	}
	cJSON *fetch_id = cJSON_Duplicate(f->fetch_id, 1);
	if (unlikely(fetch_id == NULL)) {
		goto error;
	}
	cJSON_AddItemToObject(root, "method", fetch_id);

	cJSON *param = cJSON_CreateObject();
	if (unlikely(param == NULL)) {
		goto error;
	}
	cJSON_AddItemToObject(root, "params", param);

	if (element_is_fetch_only(e)) {
		cJSON_AddTrueToObject(param, "fetchOnly");
	}

	cJSON *path = cJSON_CreateString(e->path);
	if (unlikely(path == NULL)) {
		goto error;
	}
	cJSON_AddItemToObject(param, "path", path);

	cJSON *event = cJSON_CreateString(event_name);
	if (unlikely(event == NULL)) {
		goto error;
	}
	cJSON_AddItemToObject(param, "event", event);

	if (e->value != NULL) {
		cJSON *value = cJSON_Duplicate(e->value, 1);
		if (unlikely(value == NULL)) {
			goto error;
		}
		cJSON_AddItemToObject(param, "value", value);
	}

	char *rendered_message = cJSON_PrintUnformatted(root);
	if (unlikely(rendered_message == NULL)) {
		goto error;
	}

	const struct peer *p = f->peer;
	if (unlikely(p->send_message(p, rendered_message,
			strlen(rendered_message)) != 0)) {
		cjet_free(rendered_message);
		goto error;
	}

	cJSON_Delete(root);
	cjet_free(rendered_message);

	return 0;
error:
	cJSON_Delete(root);
	return -1;
}

static int add_fetch_to_state_and_notify(const struct peer *p, struct element *e, const struct fetch *f)
{
	if (!has_access(e->fetch_groups, f->peer->fetch_groups)) {
		return 0;
	}

	if (state_matches(e, f)) {
		if (unlikely(add_fetch_to_state(e, f) != 0)) {
			log_peer_err(p, "Can't add fetch to state %s owned by %s", e->path, get_peer_name(e->peer));
			return -1;
		}
		if (unlikely(notify_fetching_peer(e, f, "add") != 0)) {
			log_peer_err(p, "Can't notify fetching peer for state %s owned by %s", e->path, get_peer_name(e->peer));
			return -1;
		}
	}
	return 0;
}

static cJSON *get_element(const struct peer *p, const struct cJSON *request, const struct element *e, const struct fetch *f, cJSON *states)
{
	if (!has_access(e->fetch_groups, f->peer->fetch_groups)) {
		return NULL;
	}

	if (state_matches(e, f)) {
		if (e->value != NULL) {
			cJSON *root = cJSON_CreateObject();
			if (unlikely(root == NULL)) {
				return create_error_response_from_request(p, request, INTERNAL_ERROR, "reason", "could not allocate memory for state object");
			}

			cJSON *path = cJSON_CreateString(e->path);
			if (unlikely(path == NULL)) {
				cJSON_Delete(root);
				return create_error_response_from_request(p, request, INTERNAL_ERROR, "reason", "could not allocate memory for path object");
			}
			cJSON_AddItemToObject(root, "path", path);

			cJSON *value = cJSON_Duplicate(e->value, 1);
			if (unlikely(value == NULL)) {
				cJSON_Delete(root);
				return create_error_response_from_request(p, request, INTERNAL_ERROR, "reason", "could not allocate memory for value");
			}

			cJSON_AddItemToObject(root, "value", value);

			cJSON_AddItemReferenceToArray(states, root);
		}
	}

	return NULL;
}

static int add_fetch_to_states_in_peer(const struct peer *p, const struct fetch *f)
{
	struct list_head *item;
	struct list_head *tmp;
	list_for_each_safe(item, tmp, &p->element_list) {
		struct element *e = list_entry(item, struct element, element_list);
		if (unlikely(add_fetch_to_state_and_notify(p, e, f) != 0)) {
			return -1;
		}
	}

	return 0;
}

static cJSON *get_elements_in_peer(const struct peer *p, const cJSON *request, const struct fetch *f, cJSON *states)
{
	struct list_head *item;
	struct list_head *tmp;
	list_for_each_safe(item, tmp, &p->element_list) {
		struct element *e = list_entry(item, struct element, element_list);
		cJSON *response = get_element(p, request, e, f, states);
		if (unlikely(response != NULL)) {
			return response;
		}
	}

	return NULL;
}

int notify_fetchers(const struct element *e, const char *event_name)
{
	for (unsigned int i = 0; i < e->fetch_table_size; i++) {
		const struct fetch *f = e->fetcher_table[i];
		if ((f != NULL) &&
				(unlikely(notify_fetching_peer(e, f, event_name) != 0))) {
			return -1;
		}
	}
	return 0;
}

cJSON *add_fetch_to_states(const struct peer *request_peer, const cJSON *request, const struct fetch *f)
{
	struct list_head *item;
	struct list_head *tmp;
	const struct list_head *peer_list = get_peer_list();
	list_for_each_safe(item, tmp, peer_list) {
		const struct peer *p = list_entry(item, struct peer, next_peer);
		int ret = add_fetch_to_states_in_peer(p, f);
		if (unlikely(ret != 0)) {
			return create_error_response_from_request(p, request, INTERNAL_ERROR, "reason", "could not add fetch to state");
		}
	}

	return create_success_response_from_request(request_peer, request);
}

static void remove_fetch_from_state(const struct element *e, const struct fetch *f)
{
	for (unsigned int i = 0; i < e->fetch_table_size; ++i) {
		if (e->fetcher_table[i] == f) {
			e->fetcher_table[i] = NULL;
		}
	}
}

static void remove_fetch_from_states_in_peer(const struct peer *p, const struct fetch *f)
{
	struct list_head *item;
	struct list_head *tmp;
	list_for_each_safe(item, tmp, &p->element_list) {
		struct element *e = list_entry(item, struct element, element_list);
		remove_fetch_from_state(e, f);
	}
}

static void remove_fetch_from_states(const struct fetch *f)
{
	struct list_head *item;
	struct list_head *tmp;
	const struct list_head *peer_list = get_peer_list();
	list_for_each_safe(item, tmp, peer_list) {
		struct peer *p = list_entry(item, struct peer, next_peer);
		remove_fetch_from_states_in_peer(p, f);
	}
}

static int find_fetchers_for_element_in_peer(const struct peer *p,
	struct element *e) {

	struct list_head *item;
	struct list_head *tmp;
	list_for_each_safe(item, tmp, &p->fetch_list) {
		struct fetch *f = list_entry(item, struct fetch, next_fetch);
		if (unlikely(add_fetch_to_state_and_notify(p, e, f) != 0)) {
			return -1;
		}
	}
	return 0;
}

int find_fetchers_for_element(struct element *e)
{
	int ret = 0;
	struct list_head *item;
	struct list_head *tmp;
	const struct list_head *peer_list = get_peer_list();
	list_for_each_safe(item, tmp, peer_list) {
		struct peer *p = list_entry(item, struct peer, next_peer);
		ret = find_fetchers_for_element_in_peer(p, e);
		if (unlikely(ret != 0)) {
			return ret;
		}
	}
	return ret;
}

cJSON *add_fetch_to_peer(struct peer *p, const cJSON *request, struct fetch **fetch_return)
{
	cJSON *response;
	const cJSON *params = get_params(p, request, &response);
	if (unlikely(params == NULL)) {
		return response;
	}

	const cJSON *matches = cJSON_GetObjectItem(params, "match");
	if (unlikely(matches != NULL)) {
		static const char deprecated[] = "No support for deprecated match";
		log_peer_err(p, deprecated);
		return create_error_response_from_request(p, request, INVALID_PARAMS, "reason", deprecated);
	}

	const cJSON *id = get_fetch_id(p, request, params, &response);
	if (unlikely(id == NULL)) {
		return response;
	}

	struct fetch *f = find_fetch(p, id);
	if (unlikely(f != NULL)) {
		return create_error_response_from_request(p, request, INVALID_PARAMS, "reason", "fetch id already in use");
	}

	f = create_fetch(p, request, id, params, &response);
	if (unlikely(f == NULL)) {
		return response;
	}

	list_add_tail(&f->next_fetch, &p->fetch_list);
	*fetch_return = f;
	return NULL;
}

cJSON *remove_fetch_from_peer(const struct peer *p, const cJSON *request)
{
	cJSON *response;
	const cJSON *params = get_params(p, request, &response);
	if (unlikely(params == NULL)) {
		return response;
	}

	const cJSON *id = get_fetch_id(p, request, params, &response);
	if (unlikely(id == NULL)) {
		return response;
	}

	struct fetch *f = find_fetch(p, id);
	if (unlikely(f == NULL)) {
		return create_error_response_from_request(p, request, INVALID_PARAMS, "reason", "fetch id not found for unfetch");
	}

	remove_fetch_from_states(f);
	list_del(&f->next_fetch);
	free_fetch(f);
	return create_success_response_from_request(p, request);
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

cJSON *get_elements(const cJSON *request, const struct peer *request_peer)
{
	cJSON *response;
	const cJSON *params = get_params(request_peer, request, &response);
	if (unlikely(params == NULL)) {
		return response;
	}

	struct fetch *f = create_fetch(request_peer, request, NULL, params, &response);
	if (unlikely(f == NULL)) {
		return response;
	}

	cJSON *states = cJSON_CreateArray();

	struct list_head *item;
	struct list_head *tmp;
	const struct list_head *peer_list = get_peer_list();
	list_for_each_safe(item, tmp, peer_list) {
		const struct peer *p = list_entry(item, struct peer, next_peer);
		response = get_elements_in_peer(p, request, f, states);
		if (unlikely(response != NULL)) {
			free_fetch(f);
			cJSON_Delete(states);
			return response;
		}
	}

	free_fetch(f);
	return create_result_response_from_request(request_peer, request, states, "result");
}
