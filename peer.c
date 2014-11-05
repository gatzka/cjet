#include <arpa/inet.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "compiler.h"
#include "config/config.h"
#include "fetch.h"
#include "hashtable.h"
#include "list.h"
#include "peer.h"
#include "state.h"

#define ROUND_UP(n,d) ((((n) + (d) - 1) / (d)) * (d))

DECLARE_HASHTABLE_UINT32(ROUTING_TABLE, CONFIG_ROUTING_TABLE_ORDER)

struct peer *alloc_peer(int fd)
{
	struct peer *p = malloc(sizeof(*p));
	if (unlikely(p == NULL)) {
		return NULL;
	}
	p->routing_table = HASHTABLE_CREATE(ROUTING_TABLE);
	if (unlikely(p->routing_table == NULL)) {
		free(p);
		return NULL;
	}
	p->io.fd = fd;
	p->op = READ_MSG_LENGTH;
	p->to_write = 0;
	p->read_ptr = p->read_buffer;
	p->write_ptr = p->read_buffer;
	INIT_LIST_HEAD(&p->next_peer);
	INIT_LIST_HEAD(&p->state_list);
	INIT_LIST_HEAD(&p->fetch_list);
	return p;
}

void free_peer(struct peer *p)
{
	remove_all_fetchers_from_peer(p);
	remove_all_states_from_peer(p);
	HASHTABLE_DELETE(ROUTING_TABLE, p->routing_table);
	free(p);
}

int copy_msg_to_write_buffer(struct peer *p, const void *rendered, uint32_t msg_len_be, size_t already_written)
{
	size_t to_write;
	uint32_t msg_len = ntohl(msg_len_be);
	size_t free_space_in_buf = CONFIG_MAX_WRITE_BUFFER_SIZE - p->to_write;
	size_t bytes_to_copy = msg_len + sizeof(msg_len_be) - already_written;

	if (unlikely(bytes_to_copy > free_space_in_buf)) {
		goto write_buffer_too_small;
	}

	char *write_buffer_ptr = p->write_buffer + p->to_write;
	if (already_written < sizeof(msg_len_be)) {
		char *msg_len_ptr = (char*)(&msg_len_be);
		msg_len_ptr += already_written;
		to_write = sizeof(msg_len_be) - already_written;
		memcpy(write_buffer_ptr, msg_len_ptr, to_write);
		write_buffer_ptr += to_write;
		already_written += to_write;
		p->to_write += to_write;
	}

	size_t msg_offset = already_written - sizeof(msg_len_be);
	const char *message_ptr = (const char *)rendered + msg_offset;
	to_write = msg_len - msg_offset;
	memcpy(write_buffer_ptr, message_ptr, to_write);
	p->to_write += to_write;

	return 0;

write_buffer_too_small:
	return -1;
}
