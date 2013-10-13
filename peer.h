#ifndef CJET_PEER_H
#define CJET_PEER_H

#include <stdint.h>

#include "config.h"

#ifdef __cplusplus
extern "C" {
#endif

struct peer {
	int fd;
	int op;
	char *read_ptr;
	char *write_ptr;
	uint32_t msg_length;
	char buffer[MAX_MESSAGE_SIZE];
};

struct peer *alloc_peer(int fd);
void free_peer(struct peer *p);

int handle_all_peer_operations(struct peer *c);

#ifdef __cplusplus
}
#endif

#endif

