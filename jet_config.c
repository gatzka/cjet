#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"
#include "compiler.h"
#include "jet_config.h"
#include "peer.h"
#include "response.h"

int process_config(cJSON *json_rpc, const struct peer *p)
{
	int ret = 0;
	cJSON *id = cJSON_GetObjectItem(json_rpc, "id");
	if (likely(id != NULL)) {
		char *rendered;

		cJSON *response = create_boolean_success_response(id, TRUE);
		if (unlikely (response == NULL)) {
			return -1;
		}
		rendered = cJSON_PrintUnformatted(response);
		if (unlikely(rendered == NULL)) {
			fprintf(stderr, "Could not render JSON into a string!\n");
			ret = -1;
			goto render_error;
		}
		ret = send_message(p, rendered, strlen(rendered));
		free(rendered);
	render_error:
		cJSON_Delete(response);
	}
	return ret;
}
