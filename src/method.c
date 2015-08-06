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

#include "cjet_io.h"
#include "compiler.h"
#include "generated/cjet_config.h"
#include "hashtable.h"
#include "jet_string.h"
#include "json/cJSON.h"
#include "list.h"
#include "method.h"
#include "peer.h"
#include "response.h"
#include "router.h"
#include "uuid.h"

DECLARE_HASHTABLE_STRING(method_table, CONFIG_METHOD_TABLE_ORDER, 1U)

static struct hashtable_string *method_hashtable = NULL;

int create_method_hashtable(void)
{
	method_hashtable = HASHTABLE_CREATE(method_table);
	if (unlikely(method_hashtable == NULL)) {
		return -1;
	}
	return 0;
}

void delete_method_hashtable(void)
{
	HASHTABLE_DELETE(method_table, method_hashtable);
}

static struct method *alloc_method(const char *path, struct peer *p)
{
	struct method *m = calloc(1, sizeof(*m));
	if (unlikely(m == NULL)) {
		log_peer_err(p, "Could not allocate memory for %s object!\n",
			"method");
		return NULL;
	}
	m->path = duplicate_string(path);
	if (unlikely(m->path == NULL)) {
		log_peer_err(p, "Could not allocate memory for %s object!\n",
			"path");
		goto alloc_path_failed;
	}
	INIT_LIST_HEAD(&m->method_list);
	m->peer = p;

	return m;

alloc_path_failed:
	free(m);
	return NULL;
}

static void free_method(struct method *m)
{
	free(m->path);
	free(m);
}

static void remove_method(struct method *m)
{
	list_del(&m->method_list);
	HASHTABLE_REMOVE(method_table, method_hashtable, m->path, NULL);
	free_method(m);
}

cJSON *add_method_to_peer(struct peer *p, const char *path)
{
	struct value_method_table val;
	int ret = HASHTABLE_GET(method_table, method_hashtable, path, &val);
	if (unlikely(ret == HASHTABLE_SUCCESS)) {
		cJSON *error = create_invalid_params_error(p, "exists", path);
		return error;
	}

	struct method *m = alloc_method(path, p);
	if (unlikely(m == NULL)) {
		cJSON *error =
		    create_internal_error(p, "reason", "not enough memory");
		return error;
	}

	struct value_method_table new_val;
	new_val.vals[0] = m;
	if (unlikely(HASHTABLE_PUT(method_table, method_hashtable, m->path, new_val, NULL) != HASHTABLE_SUCCESS)) {
		cJSON *error =
		    create_internal_error(p, "reason", "method table full");
		return error;
	}

	list_add_tail(&m->method_list, &p->method_list);
	return NULL;
}

int remove_method_from_peer(struct peer *p, const char *path)
{
	struct list_head *item;
	struct list_head *tmp;
	list_for_each_safe(item, tmp, &p->method_list) {
		struct method *m = list_entry(item, struct method, method_list);
		if (strcmp(m->path, path) == 0) {
			remove_method(m);
			return 0;
		}
	}
	return -1;
}

void remove_all_methods_from_peer(struct peer *p)
{
	struct list_head *item;
	struct list_head *tmp;
	list_for_each_safe(item, tmp, &p->method_list) {
		struct method *m = list_entry(item, struct method, method_list);
		remove_method(m);
	}
}

cJSON *call_method(struct peer *p, const char *path,
	const cJSON *args, const cJSON *json_rpc)
{
	cJSON *error;
	struct value_method_table val;
	int ret = HASHTABLE_GET(method_table, method_hashtable, path, &val);
	if (unlikely(ret != HASHTABLE_SUCCESS)) {
		error = create_invalid_params_error(p, "not exists", path);
		return error;
	}

	struct method *m = val.vals[0];
	if (unlikely(m->peer == p)) {
		error = create_invalid_params_error(
			p, "owner of method shall not call method via jet", path);
		return error;
	}

	cJSON *origin_request_id = cJSON_GetObjectItem(json_rpc, "id");
	if ((origin_request_id != NULL) &&
		 ((origin_request_id->type != cJSON_String) &&
		  (origin_request_id->type != cJSON_Number))) {
		error = create_invalid_params_error(
			p, "reason", "request id is neither string nor number");
		return error;
	}

	int routed_request_id = get_routed_request_uuid();
	cJSON *routed_message = create_routed_message(p, path, NULL, args, routed_request_id);
	if (unlikely(routed_message == NULL)) {
		error = create_internal_error(
			p, "reason", "could not create routed JSON object");
		return error;
	}

	if (unlikely(setup_routing_information(m->peer, p, origin_request_id,
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
	if (unlikely(send_message(m->peer, rendered_message,
			strlen(rendered_message)) != 0)) {
		error = create_internal_error(
			p, "reason", "could not send routing information");
	}

	free(rendered_message);

delete_json:
	cJSON_Delete(routed_message);
	return error;
}
