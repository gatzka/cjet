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

void *peer_create_wait(int fd, int epoll_fd);
void peer_unwait_delete(struct peer *p, int epoll_fd);

void handle_all_peer_operations(struct peer *c, int epoll_fd);

#endif

