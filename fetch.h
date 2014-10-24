#ifndef CJET_FETCH_H
#define CJET_FETCH_H

#include "cJSON.h"
#include "peer.h"

cJSON *add_fetch_to_peer(struct peer *p, cJSON *params);

#endif

