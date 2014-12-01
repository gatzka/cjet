#ifndef CJET_ROUTER_H
#define CJET_ROUTER_H

#include "json/cJSON.h"
#include "peer.h"

cJSON *create_routed_message(const char *path, cJSON *value, int id);
int setup_routing_information(const struct peer *routing_peer,
	struct peer *origin_peer, cJSON *origin_request_id, int id);
int handle_routing_response(cJSON *json_rpc, cJSON *response,
	const struct peer *p);

void remove_routing_info_from_peer(const struct peer *p);
void remove_peer_from_routes(const struct peer *p);

int add_routing_table(struct peer *p);
void delete_routing_table(struct peer *p);

#endif
