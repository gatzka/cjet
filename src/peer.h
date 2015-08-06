#ifndef CJET_PEER_H
#define CJET_PEER_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "config/cjet_config.h"
#include "config/os_config.h"
#include "json/cJSON.h"
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
	struct list_head method_list;
	struct list_head next_peer;
	struct list_head fetch_list;
	char *read_ptr;
	char *write_ptr;
	char *write_buffer_ptr;
	void *routing_table;
	char read_buffer[CONFIG_MAX_MESSAGE_SIZE];
	char write_buffer[CONFIG_MAX_WRITE_BUFFER_SIZE];
	char *name;
};

struct list_head *get_peer_list(void);
const char *get_peer_name(const struct peer *p);

struct peer *alloc_peer(int fd);
void free_peer(struct peer *p);
void destroy_all_peers(void);
int get_number_of_peers(void);
void remove_peer_from_routes(const struct peer *p);
void set_peer_name(struct peer *peer, const char *name);
void log_peer_err(const struct peer *p, const char *fmt, ...);

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
