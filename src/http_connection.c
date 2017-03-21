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
#include <string.h>

#include "alloc.h"
#include "buffered_reader.h"
#include "compiler.h"
#include "http-parser/http_parser.h"
#include "http_connection.h"
#include "http_server.h"
#include "log.h"
#include "util.h"

#define CRLF "\r\n"

static int on_url(http_parser *parser, const char *at, size_t length)
{
	struct http_connection *connection = container_of(parser, struct http_connection, parser);

	int is_connect;
	if (unlikely(parser->method == HTTP_CONNECT)) {
		is_connect = 1;
	} else {
		is_connect = 0;
	}
	struct http_parser_url u;
	http_parser_url_init(&u);
	int ret = http_parser_parse_url(at, length, is_connect, &u);
	if (unlikely(ret != 0)) {
		connection->status_code = HTTP_BAD_REQUEST;
		return -1;
	}
	if (likely((u.field_set & (1 << UF_PATH)) == (1 << UF_PATH))) {
		const struct url_handler *handler = find_url_handler(connection->server, at + u.field_data[UF_PATH].off, u.field_data[UF_PATH].len);
		if (handler == NULL) {
			connection->status_code = HTTP_NOT_FOUND;
			return -1;
		}
		if (handler->create != NULL) {
			(handler->create(connection));
		}

		connection->parser_settings.on_header_field = handler->on_header_field;
		connection->parser_settings.on_header_value = handler->on_header_value;
		connection->parser_settings.on_headers_complete = handler->on_headers_complete;
		connection->parser_settings.on_body = handler->on_body;
		connection->parser_settings.on_message_complete = handler->on_message_complete;
	} else {
		connection->status_code = HTTP_BAD_REQUEST;
		return -1;
	}

	return 0;
}

static const char *get_response(unsigned int status_code)
{
	switch (status_code) {
	case HTTP_BAD_REQUEST:
		return "HTTP/1.0 400 Bad Request" CRLF CRLF;
	case HTTP_NOT_FOUND:
		return "HTTP/1.0 404 Not Found" CRLF CRLF;

	case HTTP_INTERNAL_SERVER_ERROR:
	default:
		return "HTTP/1.0 500 Internal Server Error" CRLF CRLF;
	}
}

void free_connection(void *context)
{
	struct http_connection *connection = (struct http_connection *)context;

	struct buffered_reader *br = &connection->br;
	br->close(br->this_ptr);

	cjet_free(connection);
}

int send_http_error_response(struct http_connection *connection)
{
	const char *response = get_response(connection->status_code);
	struct socket_io_vector iov;
	iov.iov_base = response;
	iov.iov_len = strlen(response);

	struct buffered_reader *br = &connection->br;
	return br->writev(br->this_ptr, &iov, 1);
}

static enum bs_read_callback_return read_start_line(void *context, uint8_t *buf, size_t len)
{
	struct http_connection *connection = (struct http_connection *)context;

	if (unlikely(len == 0)) {
		free_connection(connection);
		return BS_CLOSED;
	}

	size_t nparsed = http_parser_execute(&connection->parser, &connection->parser_settings, (const char *)buf, len);

	if (unlikely(nparsed != (size_t)len)) {
		if (connection->status_code == 0) {
			connection->status_code = HTTP_BAD_REQUEST;
		}
		send_http_error_response(connection);
		free_connection(connection);
		return BS_CLOSED;
	}
	return BS_OK;
}

int init_http_connection(struct http_connection *connection, const struct http_server *server, struct buffered_reader *reader, bool is_local_connection)
{
	connection->is_local_connection = is_local_connection;
	connection->status_code = 0;
	connection->server = server;
	http_parser_settings_init(&connection->parser_settings);
	connection->parser_settings.on_url = on_url;

	http_parser_init(&connection->parser, HTTP_REQUEST);

	struct buffered_reader *br = &connection->br;
	br->this_ptr = reader->this_ptr;
	br->close = reader->close;
	br->read_exactly = reader->read_exactly;
	br->read_until = reader->read_until;
	br->writev = reader->writev;
	br->set_error_handler = reader->set_error_handler;

	return br->read_until(br->this_ptr, CRLF, read_start_line, connection);
}

struct http_connection *alloc_http_connection(void)
{
	return cjet_malloc(sizeof(struct http_connection));
}
