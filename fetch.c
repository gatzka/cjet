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
	INIT_LIST_HEAD(&f->matcher_list);
	f->peer = p;
	f->fetch_id = duplicate_string(id);
	if (unlikely(f->fetch_id == NULL)) {
		fprintf(stderr, "Could not allocate memory for fetch ID object!\n");
		free(f);
		return NULL;
	}

	return f;
}

static void free_fetch(struct fetch *f)
{
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
	while (matcher)	{
		printf("%s\n", matcher->string);
		matcher = matcher->next;
	}
	(void)f;
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
	add_matchers(f, params);
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
