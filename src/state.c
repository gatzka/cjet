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
#include "config/config.h"
#include "config/io.h"
#include "hashtable.h"
#include "jet_string.h"
#include "json/cJSON.h"
#include "list.h"
#include "peer.h"
#include "response.h"
#include "router.h"
#include "state.h"
#include "uuid.h"

DECLARE_HASHTABLE_STRING(state_table, CONFIG_STATE_TABLE_ORDER, 1U)

static struct hashtable_string *state_hashtable = NULL;

int create_state_hashtable(void)
{
    state_hashtable = HASHTABLE_CREATE(state_table);
    if (unlikely(state_hashtable == NULL)) {
        return -1;
    }
    return 0;
}

void delete_state_hashtable(void)
{
    HASHTABLE_DELETE(state_table, state_hashtable);
}

struct state *get_state(const char *path)
{
    struct value_state_table val;
    int ret = HASHTABLE_GET(state_table, state_hashtable, path, &val);
    if (ret == HASHTABLE_SUCCESS) {
        return val.vals[0];
    } else {
        return NULL;
    }
}

static struct state *alloc_state(const char *path, const cJSON *value_object,
                struct peer *p, double timeout)
{
    struct state *s = calloc(1, sizeof(*s));
    if (unlikely(s == NULL)) {
        log_peer_err(p, "Could not allocate memory for %s object!\n", "state");
        return NULL;
    }
    s->timeout = timeout;
    s->fetch_table_size = CONFIG_INITIAL_FETCH_TABLE_SIZE;
    s->fetcher_table = calloc(s->fetch_table_size, sizeof(struct fetch*));
    if (s->fetcher_table == NULL) {
        log_peer_err(p, "Could not allocate memory for fetch table!\n");
        goto alloc_fetch_table_failed;
    }

    s->path = duplicate_string(path);
    if (unlikely(s->path == NULL)) {
        log_peer_err(p, "Could not allocate memory for %s object!\n", "path");
        goto alloc_path_failed;
    }
    cJSON *value_copy = cJSON_Duplicate(value_object, 1);
    if (unlikely(value_copy == NULL)) {
        log_peer_err(p, "Could not copy value object!\n");
        goto value_copy_failed;
    }
    s->value = value_copy;
    INIT_LIST_HEAD(&s->state_list);
    s->peer = p;

    return s;

value_copy_failed:
    free(s->path);
alloc_path_failed:
    free(s->fetcher_table);
alloc_fetch_table_failed:
    free(s);
    return NULL;
}

static void free_state(struct state *s)
{
    cJSON_Delete(s->value);
    free(s->path);
    free(s->fetcher_table);
    free(s);
}

cJSON *change_state(struct peer *p, const char *path, const cJSON *value)
{
    struct value_state_table val;
    int ret = HASHTABLE_GET(state_table, state_hashtable, path, &val);
    if (unlikely(ret != HASHTABLE_SUCCESS)) {
        cJSON *error = create_invalid_params_error(p, "not exists", path);
        return error;
    }
    struct state *s = val.vals[0];
    if (unlikely(s->peer != p)) {
        cJSON *error =
            create_invalid_params_error(p, "not owner of state", path);
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
        cJSON *error =
            create_internal_error(p, "reason", "Can't notify fetching peer");
        return error;
    }
    return NULL;
}

cJSON *set_state(struct peer *p, const char *path,
    const cJSON *value, const cJSON *json_rpc)
{
    cJSON *error;
    struct value_state_table val;
    int ret = HASHTABLE_GET(state_table, state_hashtable, path, &val);
    if (unlikely(ret != HASHTABLE_SUCCESS)) {
        error = create_invalid_params_error(p, "not exists", path);
        return error;
    }
    struct state *s = val.vals[0];

    const cJSON *origin_request_id = cJSON_GetObjectItem(json_rpc, "id");
    if ((origin_request_id != NULL) &&
         ((origin_request_id->type != cJSON_String) &&
          (origin_request_id->type != cJSON_Number))) {
        error = create_invalid_params_error(
            p, "reason", "request id is neither string nor number");
        return error;
    }

    int routed_request_id = get_routed_request_uuid();
    cJSON *routed_message = create_routed_message(p, path, "value", value, routed_request_id);
    if (unlikely(routed_message == NULL)) {
        error = create_internal_error(
            p, "reason", "could not create routed JSON object");
        return error;
    }
    if (unlikely(setup_routing_information(s->peer, p, origin_request_id,
            routed_request_id) != 0)) {
        error = create_internal_error(
            p, "reason", "could not setup routing information");
        goto delete_json;
    }
    error = (cJSON *)ROUTED_MESSAGE;
    char *rendered_message = cJSON_PrintUnformatted(routed_message);
    if (unlikely(rendered_message == NULL)) {
        error = create_internal_error(
            p, "reason", "could not render message");
        goto delete_json;
    }
    if (unlikely(send_message(s->peer, rendered_message,
            strlen(rendered_message)) != 0)) {
        error = create_internal_error(
            p, "reason", "could not send routing information");
    }

    free(rendered_message);
delete_json:
    cJSON_Delete(routed_message);
    return error;
}

cJSON *add_state_to_peer(struct peer *p, const char *path, const cJSON *value)
{
    struct value_state_table val;
    int ret = HASHTABLE_GET(state_table, state_hashtable, path, &val);
    if (unlikely(ret == HASHTABLE_SUCCESS)) {
        cJSON *error = create_invalid_params_error(p, "exists", path);
        return error;
    }
    struct state *s = alloc_state(path, value, p, CONFIG_ROUTED_MESSAGES_TIMEOUT);
    if (unlikely(s == NULL)) {
        cJSON *error =
            create_internal_error(p, "reason", "not enough memory");
        return error;
    }

    if (unlikely(find_fetchers_for_state(s) != 0)) {
        cJSON *error =
            create_internal_error(p, "reason", "Can't notify fetching peer");
        free_state(s);
        return error;
    }

    struct value_state_table new_val;
    new_val.vals[0] = s;
    if (unlikely(HASHTABLE_PUT(state_table, state_hashtable, s->path, new_val, NULL) != HASHTABLE_SUCCESS)) {
        cJSON *error =
            create_internal_error(p, "reason", "state table full");
        free_state(s);
        return error;
    }

    list_add_tail(&s->state_list, &p->state_list);

    return NULL;
}

static void remove_state(struct state *s)
{
    notify_fetchers(s, "remove");
    list_del(&s->state_list);
    HASHTABLE_REMOVE(state_table, state_hashtable, s->path, NULL);
    free_state(s);
}

int remove_state_from_peer(struct peer *p, const char *path)
{
    struct list_head *item;
    struct list_head *tmp;
    list_for_each_safe(item, tmp, &p->state_list) {
        struct state *s = list_entry(item, struct state, state_list);
        if (strcmp(s->path, path) == 0) {
            remove_state(s);
            return 0;
        }
    }
    return -1;
}

void remove_all_states_from_peer(struct peer *p)
{
    struct list_head *item;
    struct list_head *tmp;
    list_for_each_safe(item, tmp, &p->state_list) {
        struct state *s = list_entry(item, struct state, state_list);
        remove_state(s);
    }
}
