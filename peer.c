#include <arpa/inet.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "compiler.h"
#include "config.h"
#include "list.h"
#include "peer.h"
#include "state.h"

#define ROUND_UP(n,d) ((((n) + (d) - 1) / (d)) * (d))

struct peer *alloc_peer(int fd)
{
	struct peer *p;
	p = malloc(sizeof(*p));
	if (unlikely(p == NULL)) {
		return NULL;
	}
	p->io.fd = fd;
	INIT_LIST_HEAD(&p->io.list);
	p->op = READ_MSG_LENGTH;
	p->to_write = 0;
	p->write_buffer = NULL;
	p->read_ptr = p->read_buffer;
	p->write_ptr = p->read_buffer;
	p->write_buffer_size = 0;
	INIT_LIST_HEAD(&p->state_list);
	return p;
}

void free_peer(struct peer *p)
{
	remove_all_states_from_peer(p);
	free(p->write_buffer);
	free(p);
}

static int allocate_new_write_buffer(struct peer *p, size_t bytes_to_copy)
{
	char *new_write_buffer;

	size_t new_buffer_size = ROUND_UP((p->write_buffer_size + bytes_to_copy), WRITE_BUFFER_CHUNK);
	if (unlikely(new_buffer_size > MAX_WRITE_BUFFER_SIZE)) {
		return -1;
	}
	new_write_buffer = realloc(p->write_buffer, new_buffer_size);
	if (new_write_buffer == NULL) {
		fprintf(stderr, "Allocation for write buffer failed!\n");
		goto realloc_failed;
	}
	p->write_buffer = new_write_buffer;
	p->write_buffer_size = new_buffer_size;
	return 0;

realloc_failed:
	return -1;
}

int copy_msg_to_write_buffer(struct peer *p, const void *rendered, uint32_t msg_len_be, size_t already_written)
{
	const char *message_ptr;
	size_t msg_offset;
	size_t to_write;
	char *write_buffer_ptr;
	uint32_t msg_len = ntohl(msg_len_be);
	size_t free_space_in_buf = p->write_buffer_size - p->to_write;
	size_t bytes_to_copy = msg_len + sizeof(msg_len_be) - already_written;

	if (bytes_to_copy > free_space_in_buf) {
		if (allocate_new_write_buffer(p, bytes_to_copy) == -1) {
			goto alloc_failed;
		}
	}

	write_buffer_ptr = p->write_buffer + p->to_write;
	if (already_written < sizeof(msg_len_be)) {
		char *msg_len_ptr = (char*)(&msg_len_be);
		msg_len_ptr += already_written;
		to_write = sizeof(msg_len_be) - already_written;
		memcpy(write_buffer_ptr, msg_len_ptr, to_write);
		write_buffer_ptr += to_write;
		already_written += to_write;
		p->to_write += to_write;
	}

	msg_offset = already_written - sizeof(msg_len_be);
	message_ptr = (const char *)rendered + msg_offset;
	to_write = msg_len - msg_offset;
	memcpy(write_buffer_ptr, message_ptr, to_write);
	p->to_write += to_write;

	return 0;

alloc_failed:
	return -1;
}
