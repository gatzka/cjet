/*
 *The MIT License (MIT)
 *
 * Copyright (c) <2016> <Stephan Gatzka>
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

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "buffered_socket.h"
#include "compiler.h"
#include "eventloop.h"
#include "http_connection.h"
#include "http_server.h"
#include "http-parser/http_parser.h"
#include "eventloop.h"
#include "log.h"
#include "util.h"

#define CRLF "\r\n"

static int on_url(http_parser *parser, const char *at, size_t length)
{
	int is_connect;
	if (parser->method == HTTP_CONNECT) {
		is_connect = 1;
	} else {
		is_connect = 0;
	}
	struct http_parser_url u;
	http_parser_url_init(&u);
	int ret = http_parser_parse_url(at, length, is_connect, &u);
	if (ret != 0) {
		return -1;
	}
	if ((u.field_set & (1 << UF_PATH)) == (1 << UF_PATH)) {
		struct http_connection *connection = container_of(parser, struct http_connection, parser);
		const struct url_handler *handler = find_url_handler(connection->server, at + u.field_data[UF_PATH].off, u.field_data[UF_PATH].len);
		if (handler->create != NULL) {
			(handler->create(connection));
		}

		connection->parser_settings.on_header_field = handler->on_header_field;
		connection->parser_settings.on_header_value = handler->on_header_value;
		connection->parser_settings.on_headers_complete = handler->on_headers_complete;
		connection->parser_settings.on_body = handler->on_body;
		connection->parser_settings.on_message_complete = handler->on_message_complete;
	}

	return 0;
}

static const char *get_response(unsigned int status_code)
{
	switch (status_code) {
	case 400:
		return "HTTP/1.0 400 Bad Request" CRLF CRLF;

	default:
		return "HTTP/1.0 500 Internal Server Error" CRLF CRLF;
	}
}

void free_connection(struct http_connection *connection)
{
	if (connection->bs) {
		buffered_socket_close(connection->bs);
		free(connection->bs);
	}
	free(connection);
}

static void free_connection_on_error(void *context)
{
	struct http_connection *connection = (struct http_connection *)context;
	free_connection(connection);
}

int send_http_error_response(struct http_connection *connection, unsigned int status_code)
{
	const char *response = get_response(status_code);
	struct buffered_socket_io_vector iov;
	iov.iov_base = response;
	iov.iov_len = strlen(response);
	return buffered_socket_writev(connection->bs, &iov, 1);
}

static enum bs_read_callback_return read_start_line(void *context, char *buf, ssize_t len)
{
	struct http_connection *connection = (struct http_connection *)context;

	if (unlikely(len == 0)) {
		free_connection(connection);
		return BS_CLOSED;
	}

	size_t nparsed = http_parser_execute(&connection->parser, &connection->parser_settings, buf, len);

	if (unlikely(nparsed != (size_t)len)) {
		send_http_error_response(connection, 400);
		free_connection(connection);
		return BS_CLOSED;
	}
	return BS_OK;
}

static int init_http_connection(struct http_connection *connection, struct http_server *server, const struct eventloop *loop, int fd)
{
	connection->server = server;
	http_parser_settings_init(&connection->parser_settings);
	connection->parser_settings.on_url = on_url;

	http_parser_init(&connection->parser, HTTP_REQUEST);
	buffered_socket_init(connection->bs, fd, loop, free_connection_on_error, connection);
	return buffered_socket_read_until(connection->bs, CRLF, read_start_line, connection);
}

struct http_connection *alloc_http_connection(struct http_server *server, const struct eventloop *loop, int fd)
{
	struct http_connection *connection = malloc(sizeof(*connection));
	if (unlikely(connection == NULL)) {
		return NULL;
	}
	connection->bs = malloc(sizeof(*(connection->bs)));
	if (unlikely(connection->bs == NULL)) {
		free(connection);
		return NULL;
	}
	int ret = init_http_connection(connection, server, loop, fd);
	if (ret == 0) {
		return connection;
	} else {
		return NULL;
	}
}
