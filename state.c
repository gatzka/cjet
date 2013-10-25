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

static struct state *alloc_state(const char *path, cJSON *value_object) {
	struct state *s;
	char *p;
	cJSON *value_copy;

	s = malloc(sizeof(*s));
	if (unlikely(s == NULL)) {
		fprintf(stderr, "Could not allocate memory for state object!\n");
		return NULL;
	}
	p = malloc(strlen(path) + 1);
	if (unlikely(p == NULL)) {
		fprintf(stderr, "Could not allocate memory for path object!\n");
		goto alloc_path_failed;
	}
	strcpy(p, path);
	s->path = p;
	value_copy = cJSON_Duplicate(value_object, 1);
	if (unlikely(value_copy == NULL)) {
		fprintf(stderr, "Could not copy value object!\n");
		goto value_copy_failed;
	}
	s->value = value_copy;
	INIT_LIST_HEAD(&s->next_state);

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
	list_add_tail(&s->next_state, &p->state_list);
	return NULL;
}

void remove_all_states_from_peer(struct peer *p) {
	struct list_head *item;
	struct list_head *tmp;
	list_for_each_safe(item, tmp, &p->state_list) {
		struct state *s = list_entry(item, struct state, next_state);
		list_del(&s->next_state);
		HASHTABLE_REMOVE(STATE_SET_TABLE, setter_hashtable, s->path);
		free_state(s);
	}
}

