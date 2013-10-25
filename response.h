#ifndef CJET_RESPONSE_H
#define CJET_RESPONSE_H

#include "cJSON.h"

static const int TRUE = 1;
static const int FALSE = 0;

cJSON *create_invalid_params_error(const char *tag, const char *reason);
cJSON *create_error_response(const cJSON *id, cJSON *error);
cJSON *create_boolean_success_response(const cJSON *id, int true_false);

#endif
