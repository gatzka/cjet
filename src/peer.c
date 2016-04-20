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

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "compiler.h"
#include "fetch.h"
#include "jet_string.h"
#include "json/cJSON.h"
#include "linux/eventloop.h"
#include "linux/linux_io.h"
#include "list.h"
#include "log.h"
#include "peer.h"
#include "router.h"
#include "state.h"
#include "util.h"

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
	remove_all_states_and_methods_from_peer(p);
	delete_routing_table(p);
	list_del(&p->next_peer);
	if (p->name != NULL) {
		free(p->name);
	}
}

static enum callback_return free_peer_on_error(union io_context *context)
{
	struct peer *p = container_of(context, struct peer, ev);
	close_and_free_peer(p);
	return CONTINUE_LOOP;
}

static int init_peer(struct peer *p, enum peer_type type, int fd, eventloop_function read_function, eventloop_function error_function)
{
	p->ev.context.fd = fd;
	p->type = type;
	p->ev.read_function = read_function;
	p->ev.write_function = 	write_msg;
	p->ev.error_function = error_function;

	if (unlikely(add_routing_table(p) != 0)) {
		return -1;
	}
	p->name = NULL;
	p->op = READ_MSG_LENGTH;
	p->to_write = 0;
	p->read_ptr = p->read_buffer;
	p->examined_ptr = p->read_ptr;
	p->write_ptr = p->read_buffer;
	INIT_LIST_HEAD(&p->next_peer);
	INIT_LIST_HEAD(&p->state_list);
	INIT_LIST_HEAD(&p->fetch_list);

	list_add_tail(&p->next_peer, &peer_list);

	if (eventloop_add_io(&p->ev) == ABORT_LOOP) {
		free_peer_resources(p);
		return -1;
	} else {
		return 0;
	}
}

struct peer *alloc_jet_peer(int fd)
{
	struct peer *p = malloc(sizeof(*p));
	if (unlikely(p == NULL)) {
		return NULL;
	}
	if (init_peer(p, JET, fd, handle_all_peer_operations, free_peer_on_error) < 0) {
		free(p);
		return NULL;
	} else {
		++number_of_peers;
		return p;
	}
}

struct ws_peer *alloc_wsjet_peer(int fd)
{
	struct ws_peer *p = malloc(sizeof(*p));
	if (unlikely(p == NULL)) {
		return NULL;
	}

	http_parser_settings_init(&p->parser_settings);
	http_parser_init (&p->parser, HTTP_REQUEST);

	if (init_peer(&p->peer, JETWS, fd, handle_ws_upgrade, free_peer_on_error) < 0) {
		free(p);
		return NULL;
	} else {
		++number_of_peers;
		return p;
	}
}

void free_peer(struct peer *p)
{
	eventloop_remove_io(&p->ev);
	free_peer_resources(p);
	--number_of_peers;
	if (p->type == JET) {
		free(p);
	} else if (p->type == JETWS) {
		struct ws_peer *ws_peer = container_of(p, struct ws_peer, peer);
		free(ws_peer);
	}
}

void close_and_free_peer(struct peer *p)
{
	int fd = p->ev.context.fd;
	free_peer(p);
	close(fd);
}

void destroy_all_peers(void)
{
	struct list_head *item;
	struct list_head *tmp;
	list_for_each_safe(item, tmp, &peer_list) {
		struct peer *p = list_entry(item, struct peer, next_peer);
		close_and_free_peer(p);
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

void set_peer_name(struct peer *peer, const char *name)
{
	if (peer->name != NULL) {
		free(peer->name);
	}
	peer->name = duplicate_string(name);
}

const char *get_peer_name(const struct peer *p)
{
	if (p->name != NULL) {
		return p->name;
	} else {
		return "unknown peer";
	}
}

#define LOG_BUFFER_SIZE 100
__attribute__((format(printf, 2, 3)))
void log_peer_err(const struct peer *p, const char *fmt, ...)
{
	int written;
	char buffer[LOG_BUFFER_SIZE];
	buffer[0] = '\0';
	written = snprintf(buffer, LOG_BUFFER_SIZE, "%s: ", get_peer_name(p));
	char *ptr = &buffer[written];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(ptr, LOG_BUFFER_SIZE - written, fmt, ap);
	va_end(ap);
	log_err("%s", buffer);
}
