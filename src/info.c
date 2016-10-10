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

#include "compiler.h"
#include "generated/version.h"
#include "info.h"
#include "json/cJSON.h"
#include "linux/linux_io.h"
#include "peer.h"
#include "response.h"

static cJSON *create_info(void)
{
	cJSON *root = cJSON_CreateObject();
	if (unlikely(root == NULL)) {
		return NULL;
	}

	cJSON *name = cJSON_CreateString(CJET_NAME);
	if (name == NULL) {
		goto error;
	}
	cJSON_AddItemToObject(root, "name", name);

	cJSON *version = cJSON_CreateString(CJET_VERSION);
	if (version == NULL) {
		goto error;
	}
	cJSON_AddItemToObject(root, "version", version);

	cJSON *protocol_version = cJSON_CreateString("1.0.0");
	if (protocol_version == NULL) {
		goto error;
	}
	cJSON_AddItemToObject(root, "protocolVersion", protocol_version);

	cJSON *features = cJSON_CreateObject();
	if (unlikely(features == NULL)) {
		goto error;
	}
	cJSON_AddItemToObject(root, "features", features);

	cJSON *batches = cJSON_CreateTrue();
	if (unlikely(batches == NULL)) {
		goto error;
	}
	cJSON_AddItemToObject(features, "batches", batches);

	cJSON *authentication = cJSON_CreateFalse();
	if (unlikely(authentication == NULL)) {
		goto error;
	}
	cJSON_AddItemToObject(features, "authentication", authentication);

	cJSON *fetch = cJSON_CreateString("full");
	if (fetch == NULL) {
		goto error;
	}
	cJSON_AddItemToObject(features, "fetch", fetch);

	return root;

error:
	cJSON_Delete(root);
	return NULL;
}

int handle_info(const cJSON *json_rpc, const struct peer *p)
{
	const cJSON *id = cJSON_GetObjectItem(json_rpc, "id");
	if (unlikely(id == NULL)) {
		log_peer_err(p, "no id in response!\n");
		return -1;
	}
	cJSON *info = create_info();
	cJSON *result = create_result_response(p, id, info, "result");

	char *rendered = cJSON_PrintUnformatted(result);
	cJSON_Delete(result);
	if (likely(rendered != NULL)) {
		int ret = p->send_message(p, rendered, strlen(rendered));
		cJSON_free(rendered);
		return ret;
	} else {
		log_peer_err(p, "Could not render JSON into a string!\n");
		return -1;
	}
}
