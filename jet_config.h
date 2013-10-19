#ifndef CJET_JET_CONFIG_H
#define CJET_JET_CONFIG_H

#include "cJSON.h"
#include "peer.h"

int process_config(cJSON *json_rpc, const struct peer *p);

#endif
