#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"
#include "compiler.h"
#include "list.h"
#include "peer.h"
#include "state.h"

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

int add_state_to_peer(struct peer *p, const char *path, cJSON *value)
{
	/*
	 * TODO: Check if the state exists in ALL peers available!
	 */
	struct state *s = alloc_state(path, value);
	if (unlikely(s == NULL)) {
		return -1;
	}
	list_add_tail(&s->next_state, &p->state_list);
	return 0;
}
