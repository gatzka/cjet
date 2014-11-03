#include <stdio.h>
#include <stdlib.h>

#include "compiler.h"
#include "fetch.h"
#include "jet_string.h"
#include "json/cJSON.h"
#include "peer.h"
#include "response.h"

static const char *get_fetch_id(cJSON *params, cJSON **err)
{
	cJSON *id = cJSON_GetObjectItem(params, "id");
	if (unlikely(id == NULL)) {
		*err = create_invalid_params_error("reason", "no fetch id given");
		return NULL;
	}
	if (unlikely(id->type != cJSON_String)) {
		*err =  create_invalid_params_error("reason", "fetch ID is not a string");
		return NULL;
	}
	*err = NULL;
	return id->valuestring;
}

static struct fetch *alloc_fetch(const struct peer *p, const char *id)
{
	struct fetch *f = calloc(1, sizeof(*f));
	if (unlikely(f == NULL)) {
		fprintf(stderr, "Could not allocate memory for fetch object!\n");
		return NULL;
	}
	INIT_LIST_HEAD(&f->next_fetch);
	f->peer = p;
	f->fetch_id = duplicate_string(id);
	if (unlikely(f->fetch_id == NULL)) {
		fprintf(stderr, "Could not allocate memory for fetch ID object!\n");
		free(f);
		return NULL;
	}

	return f;
}

static void remove_matchers(struct fetch *f)
{
	struct path_matcher *path_matcher = f->matcher;
	while (path_matcher->fetch_path != NULL)	{
		free(path_matcher->fetch_path);
		path_matcher++;
	}
}

static void free_fetch(struct fetch *f)
{
	remove_matchers(f);
	free(f->fetch_id);
	free(f);
}

static struct fetch *find_fetch(const struct peer *p, const char *id)
{
	struct list_head *item;
	struct list_head *tmp;
	list_for_each_safe(item, tmp, &p->fetch_list) {
		struct fetch *f = list_entry(item, struct fetch, next_fetch);
		if (strcmp(f->fetch_id, id) == 0) {
			return f;
		}
	}
	return NULL;
}

static int equals_match(const char *fetch_path, const char *state_path)
{
	return strcmp(fetch_path, state_path);
}

static match_func get_match_function(const char *fetch_type)
{
	if (strcmp(fetch_type, "equals") == 0) {
		return equals_match;
	}
	return NULL;
}

static cJSON *fill_matcher(struct path_matcher *matcher, const char *fetch_type, const char *path)
{
	matcher->match_function = get_match_function(fetch_type);
	if (unlikely(matcher->match_function == NULL)) {
		return create_internal_error("reason", "match function not implemented");
	}
	matcher->fetch_path = duplicate_string(path);
	if (unlikely(matcher->fetch_path == NULL)) {
		return create_internal_error("reason", "not enough memory");
	}

	return NULL;
}

static cJSON *add_path_matchers(struct fetch *f, cJSON *params)
{
	cJSON *path = cJSON_GetObjectItem(params, "path");
	if (path == NULL) {
		return NULL;
	}
	if (unlikely(path->type != cJSON_Object)) {
		return create_invalid_params_error("reason", "fetch path is not an object");
	}

	cJSON *matcher = path->child;
	struct path_matcher *path_matcher = f->matcher;
	while (matcher)	{
		if (unlikely(matcher->type != cJSON_String)) {
			return create_invalid_params_error("reason", "match path is not a string");
		}
		cJSON *error = fill_matcher(path_matcher, matcher->string, matcher->valuestring);
		if (unlikely(error != NULL)) {
			return error;
		}
		printf("%s: %s\n", matcher->string, matcher->valuestring);

		matcher = matcher->next;
		path_matcher++;
	}
	return NULL;
}

static cJSON *add_matchers(struct fetch *f, cJSON *params)
{
	cJSON *error = add_path_matchers(f, params);
	if (unlikely(error != NULL)) {
		return error;
	}
	return NULL;
}

cJSON *add_fetch_to_peer(struct peer *p, cJSON *params)
{
	cJSON *error;
	const char *id = get_fetch_id(params, &error);
	if (unlikely(id == NULL)) {
		return error;
	}
	struct fetch *f = find_fetch(p, id);
	if (unlikely(f != NULL)) {
		error = create_invalid_params_error("reason", "fetch ID already in use");
		return error;
	}

	f = alloc_fetch(p, id);
	if (unlikely(f == NULL)) {
		error = create_internal_error("reason", "not enough memory");
		return error;
	}
	error = add_matchers(f, params);
	if (unlikely(error != NULL)) {
		free_fetch(f);
		return error;
	}
	list_add_tail(&f->next_fetch, &p->fetch_list);
	return NULL;
}

void remove_all_fetchers_from_peer(struct peer *p)
{
	struct list_head *item;
	struct list_head *tmp;
	list_for_each_safe(item, tmp, &p->fetch_list) {
		struct fetch *f = list_entry(item, struct fetch, next_fetch);
		list_del(&f->next_fetch);
		free_fetch(f);
	}
}
