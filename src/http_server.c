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

#include <stddef.h>
#include <sys/types.h>

#include "http_server.h"
#include "http-parser/http_parser.h"
#include "linux/eventloop.h"
#include "linux/linux_io.h"
#include "peer.h"
#include "util.h"


#include <stdio.h>

static int on_message_begin(http_parser *parser)
{
	(void)parser;
	return 0;
}

static int on_message_complete(http_parser *parser)
{
	(void)parser;
	return 0;
}

static int on_headers_complete(http_parser *parser)
{
	(void)parser;
	return 0;
}

static void print_stuff(const char *at, size_t length)
{
	char buffer[1000];
	memcpy(buffer, at, length);
	buffer[length] = '\0';
	printf("%s\n", buffer);
}

static int on_url(http_parser *p, const char *at, size_t length)
{
	(void)p;
	printf("on url:\n");
	print_stuff(at, length);

	return 0;
}

static int on_status(http_parser *p, const char *at, size_t length)
{
	(void)p;
	printf("on status:\n");
	print_stuff(at, length);

	return 0;
}

static int on_header_field(http_parser *p, const char *at, size_t length)
{
	(void)p;
	printf("on header field:\n");
	print_stuff(at, length);

	return 0;
}

static int on_header_value(http_parser *p, const char *at, size_t length)
{
	(void)p;
	printf("on header value:\n");
	print_stuff(at, length);

	return 0;
}

static int on_body(http_parser *p, const char *at, size_t length)
{
	(void)p;
	printf("on body:\n");
	print_stuff(at, length);
	return 0;
}

#define  CRLF  "\r\n"

static const char *get_response(unsigned int status_code)
{
	switch (status_code) {
	case 400:
		return "HTTP/1.0 400 Bad Request" CRLF CRLF;

	default:
		return "HTTP/1.0 500 Internal Server Error" CRLF CRLF;
	}
}

static int send_http_error_response(struct ws_peer *ws_peer, unsigned int status_code)
{
	const char *response = get_response(status_code);
	return send_message(&ws_peer->peer, response, strlen(response));
}

void http_init(struct ws_peer *p)
{
	http_parser_settings_init(&p->parser_settings);
	p->parser_settings.on_message_begin = on_message_begin;
	p->parser_settings.on_message_complete = on_message_complete;
	p->parser_settings.on_headers_complete = on_headers_complete;
	p->parser_settings.on_url = on_url;
	p->parser_settings.on_status = on_status;
	p->parser_settings.on_header_field = on_header_field;
	p->parser_settings.on_header_value = on_header_value;
	p->parser_settings.on_body = on_body;

	http_parser_init(&p->parser, HTTP_REQUEST);
}

enum callback_return handle_ws_upgrade(union io_context *context)
{
	struct peer *p = container_of(context, struct peer, ev);
	const char *line_ptr;
	while (1) {
		ssize_t line_length = read_cr_lf_line(p, &line_ptr);
		if (line_length > 0) {
			struct ws_peer *ws_peer = container_of(p, struct ws_peer, peer);
			size_t nparsed = http_parser_execute(&ws_peer->parser, &ws_peer->parser_settings, line_ptr, line_length);
			if (ws_peer->parser.upgrade) {
			  /* handle new protocol */
			} else if (nparsed != (size_t)line_length) {
				send_http_error_response(ws_peer, 400);
				close_and_free_peer(p);
				return CONTINUE_LOOP;
			}
			reorganize_read_buffer(p);
			p->examined_ptr = p->read_ptr;
		} else {
			if (line_length == IO_WOULD_BLOCK) {
				return CONTINUE_LOOP;
			} else {
				close_and_free_peer(p);
				return CONTINUE_LOOP;
			}
		}
	}

	return CONTINUE_LOOP;
}

