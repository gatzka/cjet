#include <stdio.h>

#include "cJSON.h"
#include "compiler.h"
#include "response.h"

static cJSON *create_common_response(const cJSON *id)
{
	cJSON *root = cJSON_CreateObject();
	if (unlikely(root == NULL)) {
		return NULL;
	}

	cJSON_AddStringToObject(root, "jsonrpc", "2.0");
	switch (id->type) {

	case cJSON_String:
		cJSON_AddStringToObject(root, "id", id->valuestring);
		break;

	case cJSON_Number:
		cJSON_AddNumberToObject(root, "id", id->valueint);
		break;

	default:
		fprintf(stderr, "Unsupported method id type!");
		goto unsupported_type;

	}
	return root;

unsupported_type:
	cJSON_Delete(root);
	return NULL;
}

cJSON *create_boolean_success_response(const cJSON *id, int true_false)
{
	cJSON *root = create_common_response(id);
	if (unlikely(root == NULL)) {
		return NULL;
	}
	if (true_false == 0) {
		cJSON_AddFalseToObject(root, "result");
	} else {
		cJSON_AddTrueToObject(root, "result");
	}
	return root;
}
