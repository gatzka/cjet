#include <arpa/inet.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include "compiler.h"
#include "list.h"
#include "parse.h"
#include "peer.h"
#include "state.h"
#include "config.h"
#include "linux/peer_testing.h"

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

static void reorganize_read_buffer(struct peer *p)
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

