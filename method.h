#ifndef CJET_METHOD_H
#define CJET_METHOD_H

#include "json/cJSON.h"
#include "list.h"
#include "peer.h"

#ifdef __cplusplus
extern "C" {
#endif

struct method {
	struct list_head method_list;
	char *path;
	struct peer *peer; // The peer the method belongs to
};

int create_method_hashtable(void);
void delete_method_hashtable(void);
cJSON *add_method_to_peer(struct peer *p, const char *path);
int remove_method_from_peer(struct peer *p, const char *path);
void remove_all_methods_from_peer(struct peer *p);

#ifdef __cplusplus
}
#endif

#endif
