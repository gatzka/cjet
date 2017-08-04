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

#ifndef CJET_HTTP_CONNECTION_H
#define CJET_HTTP_CONNECTION_H

#include <stdbool.h>

#include "buffered_reader.h"
#include "http_server.h"

#ifdef __cplusplus
extern "C" {
#endif

struct http_connection {
	struct buffered_reader br;
	http_parser parser;
	http_parser_settings parser_settings;
	const struct http_server *server;
	unsigned int status_code;
	bool is_local_connection;
	unsigned int compression_level;
};

struct http_connection *alloc_http_connection(void);
int init_http_connection(struct http_connection *connection, const struct http_server *server, struct buffered_reader *reader, bool is_local_connection);
int init_http_connection2(struct http_connection *connection, const struct http_server *server, struct buffered_reader *reader, bool is_local_connection,
                          unsigned int compression_level);
void free_connection(void *context);
int send_http_error_response(struct http_connection *connection);

#define HTTP_OK 200
#define HTTP_BAD_REQUEST 400
#define HTTP_NOT_FOUND 404
#define HTTP_INTERNAL_SERVER_ERROR 500

#ifdef __cplusplus
}
#endif

#endif
