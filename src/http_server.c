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

#include "base64.h"
#include "jet_string.h"
#include "http_server.h"
#include "http-parser/http_parser.h"
#include "linux/eventloop.h"
#include "linux/linux_io.h"
#include "peer.h"
#include "sha1/sha1.h"
#include "util.h"

#define  CRLF  "\r\n"

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

static int send_upgrade_response(struct ws_peer *p)
{
	char accept_value[28];
	struct SHA1Context context;
	uint8_t sha1_buffer[SHA1HashSize];

	SHA1Reset(&context);
	SHA1Input(&context, p->sec_web_socket_key, SEC_WEB_SOCKET_GUID_LENGTH + SEC_WEB_SOCKET_KEY_LENGTH);
	SHA1Result(&context, sha1_buffer);
	b64_encode_string(sha1_buffer, SHA1HashSize, accept_value);

	static const char switch_response[] =
		"HTTP/1.1 101 Switching Protocols" CRLF
		"Upgrade: websocket" CRLF
		"Connection: Upgrade" CRLF
		"Sec-Websocket-Protocol: jet" CRLF
		"Sec-WebSocket-Accept: ";
	static const char switch_response_end[] = CRLF CRLF;

	int ret = send_ws_response(&p->peer, switch_response, sizeof(switch_response) - 1, accept_value, sizeof(accept_value), switch_response_end, sizeof(switch_response_end) - 1);
	// TODO: change read callbacks for the websocket peer
	return ret;
}

static int on_headers_complete(http_parser *parser)
{
	if (check_http_version(parser) < 0) {
		return -1;
	}
	if (parser->method != HTTP_GET) {
		return -1;
	}

	struct ws_peer *peer= container_of(parser, struct ws_peer, parser);
	if ((peer->flags.header_upgrade == 0) || (peer->flags.connection_upgrade == 0)) {
		return -1;
	}
	return send_upgrade_response(peer);
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

static int on_header_value(http_parser *p, const char *at, size_t length)
{
	int ret = 0;

	struct ws_peer *ws_peer = container_of(p, struct ws_peer, parser);

	switch(ws_peer->current_header_field) {
	case HEADER_SEC_WEBSOCKET_KEY:
		ret = save_websocket_key(ws_peer->sec_web_socket_key, at, length);
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
			ws_peer->flags.header_upgrade = 1;
		}
		break;

	case HEADER_CONNECTION_UPGRADE:
		ret = check_connection_upgrade(at, length);
		if (ret == 0) {
			ws_peer->flags.connection_upgrade = 1;
		}
		break;

	case HEADER_UNKNOWN:
	default:
		break;
	}


	ws_peer->current_header_field = HEADER_UNKNOWN;
	return ret;
}


static int on_header_field(http_parser *p, const char *at, size_t length)
{
	struct ws_peer *ws_peer = container_of(p, struct ws_peer, parser);

	static const char sec_key[] = "Sec-WebSocket-Key";
	if ((sizeof(sec_key) - 1  == length) && (jet_strncasecmp(at, sec_key, length) == 0)) {
		ws_peer->current_header_field = HEADER_SEC_WEBSOCKET_KEY;
		return 0;
	}

	static const char ws_version[] = "Sec-WebSocket-Version";
	if ((sizeof(ws_version) - 1  == length) && (jet_strncasecmp(at, ws_version, length) == 0)) {
		ws_peer->current_header_field = HEADER_SEC_WEBSOCKET_VERSION;
		return 0;
	}

	static const char ws_protocol[] = "Sec-WebSocket-Protocol";
	if ((sizeof(ws_protocol) - 1  == length) && (jet_strncasecmp(at, ws_protocol, length) == 0)) {
		ws_peer->current_header_field = HEADER_SEC_WEBSOCKET_PROTOCOL;
		return 0;
	}

	static const char header_upgrade[] = "Upgrade";
	if ((sizeof(header_upgrade) - 1  == length) && (jet_strncasecmp(at, header_upgrade, length) == 0)) {
		ws_peer->current_header_field = HEADER_UPGRADE;
		return 0;
	}

	static const char conn_upgrade[] = "Connection";
	if ((sizeof(conn_upgrade) - 1  == length) && (jet_strncasecmp(at, conn_upgrade, length) == 0)) {
		ws_peer->current_header_field = HEADER_CONNECTION_UPGRADE;
		return 0;
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
	p->parser_settings.on_header_field = on_header_field;
	p->parser_settings.on_header_value = on_header_value;

	http_parser_init(&p->parser, HTTP_REQUEST);
}

enum callback_return handle_ws_upgrade(union io_context *context)
{
	struct peer *p = container_of(context, struct peer, ev);
	(void)p;
	while (1) {
		const char *line_ptr;
		ssize_t line_length = read_cr_lf_line(p, &line_ptr);
		if (line_length > 0) {
			struct ws_peer *ws_peer = container_of(p, struct ws_peer, peer);
			size_t nparsed = http_parser_execute(&ws_peer->parser, &ws_peer->parser_settings, line_ptr, line_length);
			if (nparsed != (size_t)line_length) {
				send_http_error_response(ws_peer, 400);
				close_and_free_peer(p);
				return CONTINUE_LOOP;
			} else if (ws_peer->parser.upgrade) {
			  /* handle new protocol */
				break;
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

//	return handle_ws_protocol(context);

	return CONTINUE_LOOP;
}

