#ifndef CJET_FETCH_H
#define CJET_FETCH_H

#include "json/cJSON.h"
#include "list.h"
#include "peer.h"

typedef int (*match_func)(const char *fetch_path, const char *state_path);

struct path_matcher {
	char *fetch_path;
	match_func match_function;
	uintptr_t cookie;
};

struct fetch {
	char *fetch_id;
	const struct peer *peer;
	struct list_head next_fetch;
	struct path_matcher matcher[12];
};

cJSON *add_fetch_to_peer(struct peer *p, cJSON *params);
void remove_all_fetchers_from_peer(struct peer *p);

#endif

