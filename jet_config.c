#include <stdio.h>

#include "cJSON.h"
#include "jet_config.h"
#include "peer.h"
#include "response.h"

int process_config(cJSON *json_rpc, struct peer *p)
{
	cJSON *id = cJSON_GetObjectItem(json_rpc, "id");
	if (id != NULL) {
		cJSON *response = create_boolean_success_response(id, 1);
	}
	return 0;
}
