#ifndef CJET_PEER_H
#define CJET_PEER_H

#include <stddef.h>
#include <stdint.h>

#include "config.h"
#include "list.h"
#include "peer_testing.h"

#ifdef __cplusplus
extern "C" {
#endif

#define READ_MSG_LENGTH 0
#define READ_MSG 1
#define WRITE_MSG 2

struct peer {
	int fd;
	int op;
	int next_read_op;
	int to_write;
	uint32_t msg_length;
	uint32_t write_buffer_size;
	struct list_head state_list;
	char read_buffer[MAX_MESSAGE_SIZE];
	char *write_buffer;
	char *read_ptr;
	char *write_ptr;
	char *write_buffer_ptr;
};

struct peer *alloc_peer(int fd);
void free_peer(struct peer *p);

int handle_all_peer_operations(struct peer *c);
int send_message(struct peer *p, char *rendered, uint32_t len);

/*
 * private functions. They prototypes are just here to allow unit
 * testing.
 */
char *get_read_ptr(struct peer *p, unsigned int count);
int copy_msg_to_write_buffer(struct peer *p, const void *rendered, uint32_t msg_len_be, size_t already_written);
int send_buffer(struct peer *p);

#ifdef __cplusplus
}
#endif

#endif
