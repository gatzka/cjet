#include <stdlib.h>

#include "compiler.h"
#include "fetch.h"
#include "peer.h"
#include "response.h"

static cJSON *check_for_fetch_id(cJSON *params)
{
	cJSON *id = cJSON_GetObjectItem(params, "id");
	if (unlikely(id == NULL)) {
		return create_invalid_params_error("reason", "no fetch id given");
	}
	if (unlikely((id->type != cJSON_String) && (id->type != cJSON_Number)) ) {
		return create_invalid_params_error("reason", "fetch id is neither string nor number");
	}

	return NULL;
}

static struct fetch *alloc_fetch(void)
{
	struct fetch *f = calloc(1, sizeof(*f));
	if (unlikely(f == NULL)) {
		return NULL;
	}
	INIT_LIST_HEAD(&f->next_fetch);
	INIT_LIST_HEAD(&f->matcher_list);

	return f;
}

cJSON *add_fetch_to_peer(struct peer *p, cJSON *params)
{
	// TODO: check if fetch ID already used by this peer
	cJSON *error = check_for_fetch_id(params);
	if (unlikely(error != NULL)) {
		return error;
	}

	struct fetch *f = alloc_fetch();
	if (unlikely(f == NULL)) {
		error = create_internal_error("reason", "not enough memory");
		return error;
	}
	return NULL;
}
