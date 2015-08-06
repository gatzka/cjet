#ifndef CJET_HANDLE_STATE_H
#define CJET_HANDLE_STATE_H

#include "fetch.h"
#include "json/cJSON.h"
#include "list.h"
#include "peer.h"

#ifdef __cplusplus
extern "C" {
#endif

struct state {
	struct list_head state_list;
	char *path;
	struct peer *peer; /*The peer the state belongs to */
	cJSON *value;
	struct fetch **fetcher_table;
	double timeout;
	unsigned int fetch_table_size;
};

cJSON *change_state(struct peer *p, const char *path, const cJSON *value);
cJSON *set_state(struct peer *p, const char *path, const cJSON *value,
	const cJSON *json_rpc);
cJSON *add_state_to_peer(struct peer *p, const char *path, const cJSON *value);
int remove_state_from_peer(struct peer *p, const char *path);
void remove_all_states_from_peer(struct peer *p);

int create_state_hashtable(void);
void delete_state_hashtable(void);
struct state *get_state(const char *path);

#ifdef __cplusplus
}
#endif

#endif
