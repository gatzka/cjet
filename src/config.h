#ifndef CJET_CONFIG_H
#define CJET_CONFIG_H

#include "json/cJSON.h"
#include "peer.h"

cJSON *config_peer(struct peer *p, cJSON *params);

#endif
