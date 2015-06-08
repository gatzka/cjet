#ifndef CJET_CONFIG_H
#define CJET_CONFIG_H

#include "json/cJSON.h"
#include "peer.h"

#ifdef __cplusplus
extern "C" {
#endif

cJSON *config_peer(struct peer *p, const cJSON *params);

#ifdef __cplusplus
}
#endif

#endif
