#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "compiler.h"
#include "config/config.h"
#include "hashtable.h"
#include "jet_string.h"
#include "json/cJSON.h"
#include "list.h"
#include "peer.h"
#include "response.h"
#include "state.h"

DECLARE_HASHTABLE_STRING(STATE_TABLE, CONFIG_STATE_TABLE_ORDER, 1)

static struct hashtable_string *state_hashtable = NULL;

int create_state_hashtable(void)
{
	state_hashtable = HASHTABLE_CREATE(STATE_TABLE);
	if (unlikely(state_hashtable == NULL)) {
		return -1;
	}
	return 0;
}

void delete_state_hashtable(void)
{
	HASHTABLE_DELETE(STATE_TABLE, state_hashtable);
}

struct state *get_state(const char *path)
{
	struct value_1 *val = HASHTABLE_GET(STATE_TABLE, state_hashtable, path);
	return val->vals[0];
}

static struct state *alloc_state(const char *path, cJSON *value_object, struct peer *p) {
	struct state *s = malloc(sizeof(*s));
	if (unlikely(s == NULL)) {
		fprintf(stderr, "Could not allocate memory for %s object!\n", "state");
		return NULL;
	}
	s->path = duplicate_string(path);
	if (unlikely(s->path == NULL)) {
		fprintf(stderr, "Could not allocate memory for %s object!\n", "path");
		goto alloc_path_failed;
	}
	cJSON *value_copy = cJSON_Duplicate(value_object, 1);
	if (unlikely(value_copy == NULL)) {
		fprintf(stderr, "Could not copy value object!\n");
		goto value_copy_failed;
	}
	s->value = value_copy;
	INIT_LIST_HEAD(&s->list);
	s->peer = p;

	return s;

value_copy_failed:
	free(s->path);
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

cJSON *change_state(struct peer *p, const char *path, cJSON *value)
{
	struct value_1 *val = HASHTABLE_GET(STATE_TABLE, state_hashtable, path);
	if (unlikely(val == NULL)) {
		cJSON *error = create_invalid_params_error("not exists", path);
		return error;
	}
	struct state *s = val->vals[0];
	if (unlikely(s->peer != p)) {
		cJSON *error = create_invalid_params_error("not owner of state", path);
		return error;
	}
	cJSON *value_copy = cJSON_Duplicate(value, 1);
	/* TODO: enter state mutex for multithread IO */
	cJSON_Delete(s->value);
	s->value = value_copy;
	/* TODO: exit state mutex for multithread IO */
	// TODO: notify all clients interested in this state
	return NULL;
}

static cJSON *create_routed_message(const char *path, cJSON *value, int id)
{
	cJSON *message = cJSON_CreateObject();
	if (unlikely(message == NULL)) {
		return NULL;
	}

	cJSON *json_id = cJSON_CreateNumber(id);
	if (unlikely(json_id == NULL)) {
		goto error;
	}
	cJSON_AddItemToObject(message, "id", json_id);

	cJSON *method = cJSON_CreateString(path);
	if (unlikely(method == NULL)) {
		goto error;
	}
	cJSON_AddItemToObject(message, "method", method);

	cJSON *params = cJSON_CreateObject();
	if (unlikely(params == NULL)) {
		goto error;
	}
	cJSON_AddItemToObject(message, "params", params);

	cJSON *value_copy = cJSON_Duplicate(value, 1);
	if (unlikely(value_copy == NULL)) {
		goto error;
	}
	cJSON_AddItemToObject(params, "value", value_copy);
	return message;

error:
	fprintf(stderr, "Could not allocate memory for %s object!\n", "routed");
	cJSON_Delete(message);
	return NULL;
}

cJSON *set_state(struct peer *p, const char *path, cJSON *value)
{
	struct value_1 *val = HASHTABLE_GET(STATE_TABLE, state_hashtable, path);
	if (unlikely(val == NULL)) {
		cJSON *error = create_invalid_params_error("not exists", path);
		return error;
	}
	struct state *s = val->vals[0];
	if (unlikely(s->peer == p)) {
		cJSON *error = create_invalid_params_error("owner of state shall use change instead of set", path);
		return error;
	}
	cJSON *routed_message = create_routed_message(path, value, 1);
	if (unlikely(routed_message == NULL)) {
		cJSON *error = create_internal_error("reason", "could not create routed JSON object");
		return error;
	}
	if (unlikely(setup_routing_information(s->peer, p, value, 1) != 0)) {
		cJSON_Delete(routed_message);
		cJSON *error = create_internal_error("reason", "could not setup routing information");
		return error;
	}

	//ret = send_message(s->p, rendered, strlen(rendered));
	// if error, then remove routing information
	return NULL;
}

cJSON *add_state_to_peer(struct peer *p, const char *path, cJSON *value)
{
	struct value_1 *val = HASHTABLE_GET(STATE_TABLE, state_hashtable, path);
	if (unlikely(val != NULL)) {
		cJSON *error = create_invalid_params_error("exists", path);
		return error;
	}
	struct state *s = alloc_state(path, value, p);
	if (unlikely(s == NULL)) {
		cJSON *error = create_internal_error("reason", "not enough memory");
		return error;
	}
	struct value_1 new_val;
	new_val.vals[0] = s;
	HASHTABLE_PUT(STATE_TABLE, state_hashtable, s->path, new_val, NULL);
	list_add_tail(&s->list, &p->state_list);
	// TODO: notify all clients interested in this state
	return NULL;
}

cJSON *remove_state_from_peer(struct peer *p, const char *path)
{
	struct list_head *item;
	struct list_head *tmp;
	list_for_each_safe(item, tmp, &p->state_list) {
		struct state *s = list_entry(item, struct state, list);
		if (strcmp(s->path, path) == 0) {
		// TODO: notify all clients interested in this state
			list_del(&s->list);
			HASHTABLE_REMOVE(STATE_TABLE, state_hashtable, s->path);
			free_state(s);
			return NULL;
		}
	}
	cJSON *error = create_invalid_params_error("not exists", path);
	return error;
}

void remove_all_states_from_peer(struct peer *p) {
	struct list_head *item;
	struct list_head *tmp;
	list_for_each_safe(item, tmp, &p->state_list) {
		struct state *s = list_entry(item, struct state, list);
		// TODO: notify all clients interested in this state
		list_del(&s->list);
		HASHTABLE_REMOVE(STATE_TABLE, state_hashtable, s->path);
		free_state(s);
	}
}

