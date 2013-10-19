#ifndef CJET_PEER_H
#define CJET_PEER_H

#include <stddef.h>
#include <stdint.h>

#include "config.h"
#include "peer_testing.h"

#ifdef __cplusplus
extern "C" {
#endif

#define READ_MSG_LENGTH \
	0
#define READ_MSG \
	1
#define WRITE_OP \
	2

struct peer
{
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
int send_message(const struct peer *p, const char *rendered, size_t len);

/*
 * private functions. They prototypes are just here to allow unit
 * testing.
 */
char *get_read_ptr(struct peer *p, int count);

#ifdef __cplusplus
}
#endif

#endif
