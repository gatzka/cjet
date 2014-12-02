#ifndef CJET_FETCH_H
#define CJET_FETCH_H

#include "json/cJSON.h"
#include "list.h"
#include "peer.h"

struct path_matcher;

typedef int (*match_func)(const struct path_matcher *pm, const char *state_path);

struct path_matcher {
	char *fetch_path;
	match_func match_function;
	uintptr_t cookie;
};

struct fetch {
	char *fetch_id;
	struct peer *peer;
	struct list_head next_fetch;
	struct path_matcher matcher[12];
};

cJSON *add_fetch_to_peer(struct peer *p, cJSON *params,
	struct fetch **fetch_return);
void remove_all_fetchers_from_peer(struct peer *p);
int find_and_notify_states(struct fetch *f);

#endif

