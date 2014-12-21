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

#include <arpa/inet.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "compiler.h"
#include "config/config.h"
#include "config/io.h"
#include "fetch.h"
#include "json/cJSON.h"
#include "list.h"
#include "method.h"
#include "peer.h"
#include "router.h"
#include "state.h"

static LIST_HEAD(peer_list);

static int number_of_peers = 0;

int get_number_of_peers(void)
{
	return number_of_peers;
}

struct list_head *get_peer_list(void)
{
	return &peer_list;
}

static void free_peer_resources(struct peer *p)
{
	remove_routing_info_from_peer(p);
	remove_peer_from_routes(p);
	remove_all_fetchers_from_peer(p);
	remove_all_states_from_peer(p);
	remove_all_methods_from_peer(p);
	delete_routing_table(p);
	list_del(&p->next_peer);
	free(p);
	--number_of_peers;
}

struct peer *alloc_peer(int fd)
{
	struct peer *p = malloc(sizeof(*p));
	if (unlikely(p == NULL)) {
		return NULL;
	}
	p->io.fd = fd;
	if (unlikely(add_routing_table(p) != 0)) {
		free(p);
		return NULL;
	}
	p->op = READ_MSG_LENGTH;
	p->to_write = 0;
	p->read_ptr = p->read_buffer;
	p->write_ptr = p->read_buffer;
	INIT_LIST_HEAD(&p->next_peer);
	INIT_LIST_HEAD(&p->state_list);
	INIT_LIST_HEAD(&p->method_list);
	INIT_LIST_HEAD(&p->fetch_list);

	list_add_tail(&p->next_peer, &peer_list);
	++number_of_peers;

	if (add_io(p) < 0) {
		free_peer_resources(p);
		return NULL;
	} else {
		return p;
	}
}

void free_peer(struct peer *p)
{
	remove_io(p);
	free_peer_resources(p);
}

int copy_msg_to_write_buffer(struct peer *p, const void *rendered,
			 uint32_t msg_len_be, size_t already_written)
{
	size_t to_write;
	uint32_t msg_len = ntohl(msg_len_be);
	size_t free_space_in_buf = CONFIG_MAX_WRITE_BUFFER_SIZE - p->to_write;
	size_t bytes_to_copy =  (sizeof(msg_len_be) + msg_len) - already_written;

	if (unlikely(bytes_to_copy > free_space_in_buf)) {
		goto write_buffer_too_small;
	}

	char *write_buffer_ptr = p->write_buffer + p->to_write;
	if (already_written < sizeof(msg_len_be)) {
		char *msg_len_ptr = (char *)(&msg_len_be);
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

void destroy_all_peers(void)
{
	struct list_head *item;
	struct list_head *tmp;
	list_for_each_safe(item, tmp, &peer_list) {
		struct peer *p = list_entry(item, struct peer, next_peer);
		free_peer(p);
	}
}

void remove_peer_from_routes(const struct peer *peer_to_remove)
{
	struct list_head *item;
	struct list_head *tmp;
	list_for_each_safe(item, tmp, &peer_list) {
		struct peer *p = list_entry(item, struct peer, next_peer);
		remove_peer_from_routing_table(p, peer_to_remove);
	}
	return;
}
