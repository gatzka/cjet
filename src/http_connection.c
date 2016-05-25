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
#include <sys/types.h>

#include "base64.h"
#include "buffered_socket.h"
#include "compiler.h"
#include "jet_endian.h"
#include "jet_string.h"
#include "http_connection.h"
#include "http_server.h"
#include "http-parser/http_parser.h"
#include "eventloop.h"
#include "log.h"
#include "sha1/sha1.h"
#include "util.h"
#include "websocket_peer.h"

#define CRLF "\r\n"

#ifndef ARRAY_SIZE
# define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

static int check_http_version(const struct http_parser *parser)
{
	if (parser->http_major > 1) {
		return 0;
	}
	if ((parser->http_major == 1) && (parser->http_minor >= 1)) {
		return 0;
	} else {
		return -1;
	}
}

static int send_upgrade_response(struct http_connection *s)
{
	char accept_value[28];
	struct SHA1Context context;
	uint8_t sha1_buffer[SHA1HashSize];

	SHA1Reset(&context);
	SHA1Input(&context, s->sec_web_socket_key, SEC_WEB_SOCKET_GUID_LENGTH + SEC_WEB_SOCKET_KEY_LENGTH);
	SHA1Result(&context, sha1_buffer);
	b64_encode_string(sha1_buffer, SHA1HashSize, accept_value);

	static const char switch_response[] =
		"HTTP/1.1 101 Switching Protocols" CRLF
		"Upgrade: websocket" CRLF
		"Connection: Upgrade" CRLF
		"Sec-Websocket-Protocol: jet" CRLF
		"Sec-WebSocket-Accept: ";
	static const char switch_response_end[] = CRLF CRLF;

	struct buffered_socket_io_vector iov[3];
	iov[0].iov_base = switch_response;
	iov[0].iov_len = sizeof(switch_response ) - 1;
	iov[1].iov_base = accept_value;
	iov[1].iov_len = sizeof(accept_value);
	iov[2].iov_base = switch_response_end;
	iov[2].iov_len = sizeof(switch_response_end) - 1;
	return buffered_socket_writev(s->bs, iov, ARRAY_SIZE(iov));
}

static int on_headers_complete(http_parser *parser)
{
	if (check_http_version(parser) < 0) {
		return -1;
	}
	if (parser->method != HTTP_GET) {
		return -1;
	}

	struct http_connection *connection = container_of(parser, struct http_connection, parser);
	if ((connection->flags.header_upgrade == 0) || (connection->flags.connection_upgrade == 0)) {
		return -1;
	}
	return send_upgrade_response(connection);
}

static int save_websocket_key(uint8_t *dest, const char *at, size_t length)
{
	static const char ws_guid[SEC_WEB_SOCKET_GUID_LENGTH] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

	if (length == SEC_WEB_SOCKET_KEY_LENGTH) {
		memcpy(dest, at, length);
		memcpy(&dest[length], ws_guid, sizeof(ws_guid));
		return 0;
	} else {
		return -1;
	}
}

static int check_websocket_version(const char *at, size_t length)
{
	static const char version[] = "13";
	if ((length == sizeof(version) - 1) && (memcmp(at, version, length) == 0)) {
		return 0;
	} else {
		return -1;
	}
}

static int check_websocket_protocol(const char *at, size_t length)
{
	static const char proto[] ="jet";
	//TODO: There might be more protocols than just jet. We habe to parse the list and look if jet is in the list.
	if ((length == sizeof(proto) - 1) && (memcmp(at, proto, length) == 0)) {
		return 0;
	} else {
		return -1;
	}
}

static int check_upgrade(const char *at, size_t length)
{
	static const char upgrade[] ="websocket";
	if ((length == sizeof(upgrade) - 1) && (jet_strncasecmp(at, upgrade, length) == 0)) {
		return 0;
	} else {
		return -1;
	}
}

static int check_connection_upgrade(const char *at, size_t length)
{
	static const char upgrade[] ="Upgrade";
	if ((length == sizeof(upgrade) - 1) && (jet_strncasecmp(at, upgrade, length) == 0)) {
		return 0;
	} else {
		return -1;
	}
}

static int on_url(http_parser *parser, const char *at, size_t length)
{
	(void)parser;
	(void)at;
	(void)length;

	struct http_parser_url u;
	http_parser_url_init(&u);
	int ret = http_parser_parse_url(at, length, 0, &u);
	(void)ret;

	return 0;
}

static int on_header_field(http_parser *p, const char *at, size_t length)
{
	struct http_connection *connection = container_of(p, struct http_connection, parser);

	static const char sec_key[] = "Sec-WebSocket-Key";
	if ((sizeof(sec_key) - 1  == length) && (jet_strncasecmp(at, sec_key, length) == 0)) {
		connection->current_header_field = HEADER_SEC_WEBSOCKET_KEY;
		return 0;
	}

	static const char ws_version[] = "Sec-WebSocket-Version";
	if ((sizeof(ws_version) - 1  == length) && (jet_strncasecmp(at, ws_version, length) == 0)) {
		connection->current_header_field = HEADER_SEC_WEBSOCKET_VERSION;
		return 0;
	}

	static const char ws_protocol[] = "Sec-WebSocket-Protocol";
	if ((sizeof(ws_protocol) - 1  == length) && (jet_strncasecmp(at, ws_protocol, length) == 0)) {
		connection->current_header_field = HEADER_SEC_WEBSOCKET_PROTOCOL;
		return 0;
	}

	static const char header_upgrade[] = "Upgrade";
	if ((sizeof(header_upgrade) - 1  == length) && (jet_strncasecmp(at, header_upgrade, length) == 0)) {
		connection->current_header_field = HEADER_UPGRADE;
		return 0;
	}

	static const char conn_upgrade[] = "Connection";
	if ((sizeof(conn_upgrade) - 1  == length) && (jet_strncasecmp(at, conn_upgrade, length) == 0)) {
		connection->current_header_field = HEADER_CONNECTION_UPGRADE;
		return 0;
	}

	return 0;
}

static int on_header_value(http_parser *p, const char *at, size_t length)
{
	int ret = 0;

	struct http_connection *connection = container_of(p, struct http_connection, parser);

	switch(connection->current_header_field) {
	case HEADER_SEC_WEBSOCKET_KEY:
		ret = save_websocket_key(connection->sec_web_socket_key, at, length);
		break;

	case HEADER_SEC_WEBSOCKET_VERSION:
		ret = check_websocket_version(at, length);
		break;

	case HEADER_SEC_WEBSOCKET_PROTOCOL:
		ret = check_websocket_protocol(at, length);
		break;

	case HEADER_UPGRADE:
		ret = check_upgrade(at, length);
		if (ret == 0) {
			connection->flags.header_upgrade = 1;
		}
		break;

	case HEADER_CONNECTION_UPGRADE:
		ret = check_connection_upgrade(at, length);
		if (ret == 0) {
			connection->flags.connection_upgrade = 1;
		}
		break;

	case HEADER_UNKNOWN:
	default:
		break;
	}

	connection->current_header_field = HEADER_UNKNOWN;
	return ret;
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

static void free_connection(struct http_connection *connection)
{
	if (connection->bs) {
		buffered_socket_close(connection->bs);
	}
	free(connection);
}

static void free_connection_on_error(void *context)
{
	struct http_connection *connection = (struct http_connection *)context;
	free_connection(connection);
}

static int send_http_error_response(struct http_connection *connection, unsigned int status_code)
{
	const char *response = get_response(status_code);
	struct buffered_socket_io_vector iov;
	iov.iov_base = response;
	iov.iov_len = strlen(response);
	return buffered_socket_writev(connection->bs, &iov, 1);
}

static void read_header_line(void *context, char *buf, ssize_t len)
{
	struct http_connection *connection = (struct http_connection *)context;

	if (likely(len > 0)) {
		size_t nparsed = http_parser_execute(&connection->parser, &connection->parser_settings, buf, len);

		if (nparsed != (size_t)len) {
			send_http_error_response(connection, 400);
			free_connection(connection);
		} else if (connection->parser.upgrade) {
			struct websocket_peer *ws_peer = alloc_websocket_peer(connection->bs);
			if(ws_peer == NULL) {
				send_http_error_response(connection, 500);
				log_err("Could not allocate websocket peer!\n");
			} else {
				connection->bs = NULL;
			}
			free_connection(connection);
		} else {
			buffered_socket_read_until(connection->bs, CRLF, read_header_line, connection);
		}
	} else {
		if (len < 0) {
			log_err("Error while reading header line!\n");
		}
		free_connection(connection);
	}
}

static void read_start_line(void *context, char *buf, ssize_t len)
{
	struct http_connection *connection = (struct http_connection *)context;

	if (likely(len > 0)) {
		size_t nparsed = http_parser_execute(&connection->parser, &connection->parser_settings, buf, len);
		
		if (nparsed != (size_t)len) {
			send_http_error_response(connection, 400);
			free_connection(connection);
		}

		buffered_socket_read_until(connection->bs, CRLF, read_header_line, connection);
	} else {
		if (len < 0) {
			log_err("Error while reading start line!\n");
		}
		free_connection(connection);
	}
}

static void init_http_connection(struct http_connection *connection, struct io_event *ev, int fd)
{
	struct http_server *server = container_of(ev, struct http_server, ev);
	connection->server = server;
	http_parser_settings_init(&connection->parser_settings);
	connection->parser_settings.on_headers_complete = on_headers_complete;
	connection->parser_settings.on_header_field = on_header_field;
	connection->parser_settings.on_header_value = on_header_value;
	connection->parser_settings.on_url = on_url;

	http_parser_init(&connection->parser, HTTP_REQUEST);
	buffered_socket_init(connection->bs, fd, ev->loop, free_connection_on_error, connection);
	buffered_socket_read_until(connection->bs, CRLF, read_start_line, connection);
}

struct http_connection *alloc_http_connection(struct io_event *ev, int fd)
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
	init_http_connection(connection, ev, fd);
	return connection;
}
