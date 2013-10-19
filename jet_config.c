#include <stdio.h>

#include "cJSON.h"
#include "compiler.h"
#include "jet_config.h"
#include "peer.h"
#include "response.h"

int process_config(cJSON *json_rpc, const struct peer *p)
{
	cJSON *id = cJSON_GetObjectItem(json_rpc, "id");
	if (likely(id != NULL)) {
		cJSON *response = create_boolean_success_response(id, 1);
		if (unlikely (response == NULL)) {
			return -1;
		}
		cJSON_Delete(response);
	}
	return 0;
}
