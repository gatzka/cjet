#ifndef CJET_STATE_H
#define CJET_STATE_H

#include "cJSON.h"
#include "peer.h"

int add_state_to_peer(struct peer *p, const char *path, cJSON *value);

#endif
