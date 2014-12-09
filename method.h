#ifndef CJET_METHOD_H
#define CJET_METHOD_H

#include "json/cJSON.h"

#include "peer.h"

int create_method_hashtable(void);
void delete_method_hashtable(void);
cJSON *add_method_to_peer(struct peer *p, const char *path);

#endif
