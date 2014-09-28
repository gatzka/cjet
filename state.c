#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"
#include "compiler.h"
#include "config.h"
#include "hashtable.h"
#include "list.h"
#include "peer.h"
#include "response.h"
#include "state.h"

DECLARE_HASHTABLE_STRING(STATE_SET_TABLE, STATE_SET_TABLE_ORDER)

static struct hashtable_string *setter_hashtable = NULL;

int create_setter_hashtable(void)
{
	setter_hashtable = HASHTABLE_CREATE(STATE_SET_TABLE);
	if (unlikely(setter_hashtable == NULL)) {
		return -1;
	}
	return 0;
}

void delete_setter_hashtable(void)
{
	HASHTABLE_DELETE(STATE_SET_TABLE, setter_hashtable);
}

struct state *get_state(const char *path)
{
	return HASHTABLE_GET(STATE_SET_TABLE, setter_hashtable, path);
}

static struct state *alloc_state(const char *path, cJSON *value_object) {
	struct state *s;
	char *p;
	size_t path_length;
	cJSON *value_copy;

	s = malloc(sizeof(*s));
	if (unlikely(s == NULL)) {
		fprintf(stderr, "Could not allocate memory for state object!\n");
		return NULL;
	}
	path_length = strlen(path);
	p = malloc(path_length + 1);
	if (unlikely(p == NULL)) {
		fprintf(stderr, "Could not allocate memory for path object!\n");
		goto alloc_path_failed;
	}
	strncpy(p, path, path_length);
	p[path_length] = '\0';
	s->path = p;
	value_copy = cJSON_Duplicate(value_object, 1);
	if (unlikely(value_copy == NULL)) {
		fprintf(stderr, "Could not copy value object!\n");
		goto value_copy_failed;
	}
	s->value = value_copy;
	INIT_LIST_HEAD(&s->list);

	return s;

value_copy_failed:
	free(p);
alloc_path_failed:
	free(s);
	return NULL;
}

static void free_state(struct state *s)
{
	cJSON_Delete(s->value);
	free(s->path);
	free(s);
}

cJSON *change_state(const char *path, cJSON *value)
{
	struct state *s = HASHTABLE_GET(STATE_SET_TABLE, setter_hashtable, path);
	if (unlikely(s == NULL)) {
		cJSON *error = create_invalid_params_error("not exists", path);
		return error;
	}
	cJSON *value_copy = cJSON_Duplicate(value, 1);
	/* TODO: enter state mutex for multithread IO */
	cJSON_Delete(s->value);
	s->value = value_copy;
	/* TODO: exit state mutex for multithread IO */
	return NULL;
}

cJSON *add_state_to_peer(struct peer *p, const char *path, cJSON *value)
{
	struct state *s = HASHTABLE_GET(STATE_SET_TABLE, setter_hashtable, path);
	if (unlikely(s != NULL)) {
		cJSON *error = create_invalid_params_error("exists", path);
		return error;
	}
	s = alloc_state(path, value);
	if (unlikely(s == NULL)) {
		cJSON *error = create_invalid_params_error("reason", "not enough memory");
		return error;
	}
	HASHTABLE_PUT(STATE_SET_TABLE, setter_hashtable, s->path, s, NULL);
	list_add_tail(&s->list, &p->state_list);
	// TODO: notify all clients interested in this state
	return NULL;
}

cJSON *remove_state_from_peer(struct peer *p, const char *path)
{
	struct list_head *item;
	struct list_head *tmp;
	cJSON *error;
	list_for_each_safe(item, tmp, &p->state_list) {
		struct state *s = list_entry(item, struct state, list);
		if (strcmp(s->path, path) == 0) {
		// TODO: notify all clients interested in this state
			list_del(&s->list);
			HASHTABLE_REMOVE(STATE_SET_TABLE, setter_hashtable, s->path);
			free_state(s);
			return NULL;
		}
	}
	error = create_invalid_params_error("notExists", path);
	return error;
}

void remove_all_states_from_peer(struct peer *p) {
	struct list_head *item;
	struct list_head *tmp;
	list_for_each_safe(item, tmp, &p->state_list) {
		struct state *s = list_entry(item, struct state, list);
		// TODO: notify all clients interested in this state
		list_del(&s->list);
		HASHTABLE_REMOVE(STATE_SET_TABLE, setter_hashtable, s->path);
		free_state(s);
	}
}

