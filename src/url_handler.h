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

#ifndef CJET_URL_HANDLER_H
#define CJET_URL_HANDLER_H

#include <stddef.h>

#include "http-parser/http_parser.h"
#include "http_connection.h"

#ifdef __cplusplus
extern "C" {
#endif

struct http_connection;

struct url_handler {
	const char *request_target;

	int (*create)(struct http_connection *connection);
	int (*on_header_field)(http_parser *parser, const char *at, size_t length);
	int (*on_header_value)(http_parser *parser, const char *at, size_t length);
	int (*on_headers_complete)(http_parser *parser);
	int (*on_body)(http_parser *parser, const char *at, size_t length);
	int (*on_message_complete)(http_parser *parser);
};

#ifdef __cplusplus
}
#endif

#endif
