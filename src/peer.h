/*
 *The MIT License (MIT)
 *
 * Copyright (c) <2014> <Stephan Gatzka>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef CJET_PEER_H
#define CJET_PEER_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "generated/cjet_config.h"
#include "generated/os_config.h"
#include "json/cJSON.h"
#include "list.h"
#include "linux/eventloop.h"

#ifdef __cplusplus
extern "C" {
#endif

#define READ_MSG_LENGTH 0
#define READ_MSG 1

struct peer {
	struct io_event ev;
	int op;
	unsigned int to_write;
	uint32_t msg_length;
	size_t write_buffer_size;
	struct list_head state_list;
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

struct peer *alloc_jet_peer(int fd);
struct peer *alloc_wsjet_peer(int fd);
void close_and_free_peer(struct peer *p);
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
