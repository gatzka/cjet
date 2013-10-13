#ifndef CJET_PEER_H
#define CJET_PEER_H

#include <stdint.h>

#include "config.h"

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

void peer_unwait_delete(struct peer *p, int epoll_fd);

int handle_all_peer_operations(struct peer *c, int epoll_fd);

#endif

