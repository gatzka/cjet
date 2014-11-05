#ifndef CJET_STATE_H
#define CJET_STATE_H

#include "json/cJSON.h"
#include "list.h"
#include "peer.h"

#ifdef __cplusplus
extern "C" {
#endif

struct state {
	struct list_head list;
	char *path;
	struct peer *peer; // The peer the state belongs to
	cJSON *value;
};

cJSON *change_state(struct peer *p, const char *path, cJSON *value);
cJSON *add_state_to_peer(struct peer *p, const char *path, cJSON *value);
cJSON *remove_state_from_peer(struct peer *p, const char *path);
void remove_all_states_from_peer(struct peer *p);

int create_state_hashtable(void);
void delete_state_hashtable(void);
struct state *get_state(const char *path);

#ifdef __cplusplus
}
#endif

#endif
