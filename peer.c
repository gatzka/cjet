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
#include "fetch.h"
#include "hashtable.h"
#include "json/cJSON.h"
#include "list.h"
#include "peer.h"
#include "state.h"

DECLARE_HASHTABLE_UINT32(routing_table, CONFIG_ROUTING_TABLE_ORDER, 2)

struct peer *alloc_peer(int fd)
{
	struct peer *p = malloc(sizeof(*p));
	if (unlikely(p == NULL)) {
		return NULL;
	}
	p->routing_table = HASHTABLE_CREATE(routing_table);
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

static void remove_routing_information_from_peer(struct peer *p)
{
	unsigned int i;
	struct hashtable_u32 *table = p->routing_table;
	for (i = 0; i < table_size_routing_table; ++i) {
		struct hashtable_u32 *entry = &(table[i]);
		if (entry->key != (u32)HASHTABLE_INVALIDENTRY) {
			struct value_2 val = HASHTABLE_REMOVE(
				routing_table, p->routing_table, entry->key);
				/* struct peer *origin_peer = val.vals[0];
				 * TODO: the origin peer should be notified
				 */
			cJSON *value = val.vals[1];
			cJSON_Delete(value);
		}
	}
}

void free_peer(struct peer *p)
{
	remove_routing_information_from_peer(p);
	remove_all_fetchers_from_peer(p);
	remove_all_states_from_peer(p);
	HASHTABLE_DELETE(routing_table, p->routing_table);
	free(p);
}

int copy_msg_to_write_buffer(struct peer *p, const void *rendered,
			 uint32_t msg_len_be, size_t already_written)
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

int setup_routing_information(struct peer *routing_peer,
			 struct peer *origin_peer, cJSON *value, int id)
{
	cJSON *value_copy = cJSON_Duplicate(value, 1);
	if (unlikely(value_copy == NULL)) {
		fprintf(stderr, "Could not copy value object!\n");
		return -1;
	}
	struct value_2 val;
	val.vals[0] = origin_peer;
	val.vals[1] = value_copy;
	if (unlikely(HASHTABLE_PUT(routing_table, routing_peer->routing_table,
				 id, val, NULL) != 0)) {
		cJSON_Delete(value_copy);
	}
	return 0;
}

int handle_routing_response(cJSON *json_rpc, cJSON *response, struct peer *p)
{
	cJSON *id = cJSON_GetObjectItem(json_rpc, "id");
	if (unlikely(id == NULL)) {
		fprintf(stderr, "no id in response!\n");
		return -1;
	}
	if (unlikely(id->type != cJSON_Number)) {
		fprintf(stderr, "id is not a number!\n");
		return -1;
	}
	struct value_2 *val =
		 HASHTABLE_GET(routing_table, p->routing_table, id->valueint);
	if (val != NULL) {
		printf("got routed answer!\n");
		char *res = cJSON_Print(response);
		printf("%s\n", res);
		free(res);
	}

	/* REMOVE_HASHTABLE_ENTRY */
	return 0;
}
