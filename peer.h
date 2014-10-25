#ifndef CJET_PEER_H
#define CJET_PEER_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "config/config.h"
#include "config/peer_io.h"
#include "list.h"

#ifdef __cplusplus
extern "C" {
#endif

#define READ_MSG_LENGTH 0
#define READ_MSG 1
#define WRITE_MSG 2

struct peer {
	struct io io;
	int op;
	int next_read_op;
	unsigned int to_write;
	uint32_t msg_length;
	size_t write_buffer_size;
	struct list_head state_list;
	struct list_head next_peer;
	struct list_head fetch_list;
	char *read_ptr;
	char *write_ptr;
	char *write_buffer_ptr;
	char read_buffer[CONFIG_MAX_MESSAGE_SIZE];
	char write_buffer[CONFIG_MAX_WRITE_BUFFER_SIZE];
};

struct peer *alloc_peer(int fd);
void free_peer(struct peer *p);
int copy_msg_to_write_buffer(struct peer *p, const void *rendered, uint32_t msg_len_be, size_t already_written);

static inline ptrdiff_t unread_space(const struct peer *p)
{
	return &(p->read_buffer[CONFIG_MAX_MESSAGE_SIZE]) - p->read_ptr;
}

static inline ptrdiff_t free_space(const struct peer *p)
{
	return &(p->read_buffer[CONFIG_MAX_MESSAGE_SIZE]) - p->write_ptr;
}

static inline void reorganize_read_buffer(struct peer *p)
{
	ptrdiff_t unread = p->write_ptr - p->read_ptr;
	if (unread != 0) {
		memmove(p->read_buffer, p->read_ptr, (size_t)unread);
		p->write_ptr = p->read_buffer + unread;
	} else {
		p->write_ptr = p->read_buffer;
	}
	p->read_ptr = p->read_buffer;
}

#ifdef __cplusplus
}
#endif

#endif
