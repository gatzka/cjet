#ifndef CJET_ROUTER_H
#define CJET_ROUTER_H

#include "json/cJSON.h"
#include "peer.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ROUTED_MESSAGE -1

cJSON *create_routed_message(const struct peer *p, const char *path, const char *name,
	const cJSON *value, int id);
int setup_routing_information(const struct peer *routing_peer,
	struct peer *origin_peer, const cJSON *origin_request_id, int id);
int handle_routing_response(const cJSON *json_rpc, const cJSON *response,
	const struct peer *p);

void remove_routing_info_from_peer(const struct peer *p);
void remove_peer_from_routing_table(const struct peer *p,
	const struct peer *peer_to_remove);

int add_routing_table(struct peer *p);
void delete_routing_table(struct peer *p);

#ifdef __cplusplus
}
#endif

#endif
