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

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "base64.h"
#include "compiler.h"
#include "jet_endian.h"
#include "jet_string.h"
#include "http_server.h"
#include "http-parser/http_parser.h"
#include "eventloop.h"
#include "linux/linux_io.h"
#include "log.h"
#include "parse.h"
#include "peer.h"
#include "sha1/sha1.h"
#include "util.h"

#define  CRLF  "\r\n"

static const uint8_t WS_MASK_SET = 0x80;
static const uint8_t WS_HEADER_FIN = 0x80;

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

	int ret = send_ws_upgrade_response(p, switch_response, sizeof(switch_response) - 1, accept_value, sizeof(accept_value), switch_response_end, sizeof(switch_response_end) - 1);
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
	struct peer *p = &ws_peer->s_peer.peer;
	return p->send_message(p, response, strlen(response));
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

static int ws_get_header(struct ws_peer *p)
{
	char *read_ptr;
	uint8_t field;

	ssize_t ret = get_read_ptr(&p->s_peer, sizeof(field), &read_ptr);
	if (unlikely(ret <= 0)) {
		if (ret == IO_WOULD_BLOCK) {
			return 0;
		}
	} else {
		memcpy(&field, read_ptr, 1);
		if ((field & WS_HEADER_FIN) == WS_HEADER_FIN) {
			p->ws_flags.fin = 1;
		}

		static const uint8_t OPCODE_MASK = 0x0f;
		field = field & OPCODE_MASK;
		p->ws_flags.opcode = field;

		p->ws_protocol = WS_READING_FIRST_LENGTH;
	}
	return ret;
}

static void switch_state_after_length(struct ws_peer *p)
{
	if (p->ws_flags.mask == 1) {
		p->ws_protocol = WS_READING_MASK;
	} else {
		p->ws_protocol = WS_READING_PAYLOAD;
	}
}

static int ws_get_first_length(struct ws_peer *p)
{
	char *read_ptr;
	uint8_t field;

	ssize_t ret = get_read_ptr(&p->s_peer, sizeof(field), &read_ptr);
	if (unlikely(ret <= 0)) {
		if (ret == IO_WOULD_BLOCK) {
			return 0;
		}
	} else {
		memcpy(&field, read_ptr, sizeof(field));
		p->ws_protocol = WS_READING_FIRST_LENGTH;
		if ((field & WS_MASK_SET) == WS_MASK_SET) {
			p->ws_flags.mask = 1;
		}
		field = field & ~WS_MASK_SET;
		if (field < 126) {
			p->length = field;
			switch_state_after_length(p);
		} else if (field == 126) {
			p->ws_protocol = WS_READING_LENGTH16;
		} else {
			p->ws_protocol = WS_READING_LENGTH64;
		}
	}
	return ret;
}

static int ws_get_length16(struct ws_peer *p)
{
	char *read_ptr;
	uint16_t field;

	ssize_t ret = get_read_ptr(&p->s_peer, sizeof(field), &read_ptr);
	if (unlikely(ret <= 0)) {
		if (ret == IO_WOULD_BLOCK) {
			return 0;
		}
	} else {
		memcpy(&field, read_ptr, sizeof(field));
		field = jet_be16toh(field);
		p->length = field;
		switch_state_after_length(p);
	}
	return ret;
}

static int ws_get_length64(struct ws_peer *p)
{
	char *read_ptr;
	uint64_t field;

	ssize_t ret = get_read_ptr(&p->s_peer, sizeof(field), &read_ptr);
	if (unlikely(ret <= 0)) {
		if (ret == IO_WOULD_BLOCK) {
			return 0;
		}
	} else {
		memcpy(&field, read_ptr, sizeof(field));
		field = jet_be64toh(field);
		p->length = field;
		switch_state_after_length(p);
	}
	return ret;
}

static int ws_get_mask(struct ws_peer *p)
{
	char *read_ptr;

	ssize_t ret = get_read_ptr(&p->s_peer, sizeof(p->mask), &read_ptr);
	if (unlikely(ret <= 0)) {
		if (ret == IO_WOULD_BLOCK) {
			return 0;
		}
	} else {
		memcpy(p->mask, read_ptr, sizeof(p->mask));
		p->ws_protocol = WS_READING_PAYLOAD;
	}
	return ret;
}

static void unmask_payload(char *buffer, uint8_t *mask, unsigned int length)
{
	for (unsigned int i= 0; i < length; i++) {
		buffer[i] = buffer[i] ^ (mask[i % 4]);
	}
}

static int ws_handle_frame(struct ws_peer *ws_peer, char *msg, unsigned int length)
{
	int ret;
	switch (ws_peer->ws_flags.opcode) {
	case WS_CONTINUATION_FRAME:
		log_err("Fragmented websocket frame not supported!\n");
		//TODO: close_websocket
		break;

	case WS_BINARY_FRAME:
	case WS_TEXT_FRAME:
		ret = parse_message(msg, length, &ws_peer->s_peer.peer);
		if (unlikely(ret == -1)) {
			return -1;
		}
		break;

	case WS_PING_FRAME:

		break;

	case WS_PONG_FRAME:

		break;

	case WS_CLOSE_FRAME:

		break;

	default:
		log_err("Unsupported websocket frame!\n");
		//TODO: close_websocket
		break;
	}

	return 0;
}

static int ws_read_payload(struct ws_peer *p)
{
	char *read_ptr;

	if (unlikely(p->length > UINT_MAX)) {
		log_err("Too much data to read!\n");
		return IO_ERROR;
	}
	unsigned int length = (unsigned int)p->length;
	ssize_t ret = get_read_ptr(&p->s_peer, length, &read_ptr);
	if (unlikely(ret <= 0)) {
		if (ret == IO_WOULD_BLOCK) {
			return 0;
		}
	} else {
		// TODO: check if mask bit is set
		unmask_payload(read_ptr, p->mask, length);
		ret = ws_handle_frame(p, read_ptr, length);
		p->ws_protocol = WS_READING_HEADER;
		if (unlikely(ret == -1)) {
			return -1;
		}
		reorganize_read_buffer(&p->s_peer);
	}
	return ret;
}

static enum callback_return handle_ws_protocol(const struct eventloop *loop, union io_context *ctx)
{
	(void)loop; // TODO

	struct io_event *ev = container_of(ctx, struct io_event, context);
	struct socket_peer *p = container_of(ev, struct socket_peer, ev);
	struct ws_peer *ws_peer = container_of(p, struct ws_peer, s_peer);

	while (1) {
		int ret;
		switch (ws_peer->ws_protocol) {
		case WS_READING_HEADER:
			ret = ws_get_header(ws_peer);
			break;

		case WS_READING_FIRST_LENGTH:
			ret = ws_get_first_length(ws_peer);
			break;

		case WS_READING_LENGTH16:
			ret = ws_get_length16(ws_peer);
			break;

		case WS_READING_LENGTH64:
			ret = ws_get_length64(ws_peer);
			break;

		case WS_READING_MASK:
			ret = ws_get_mask(ws_peer);
			break;

		case WS_READING_PAYLOAD:
			ret = ws_read_payload(ws_peer);
			break;

		default:
			log_err("Unknown websocket operation!\n");
			ret = -1;
			break;
		}

		if (unlikely(ret <= 0)) {
			if (unlikely(ret < 0)) {
				p->peer.close(&p->peer);
			}
			return CONTINUE_LOOP;
		}
	}
	return CONTINUE_LOOP;
}

enum callback_return handle_ws_upgrade(const struct eventloop *loop, union io_context *ctx)
{

	struct io_event *ev = container_of(ctx, struct io_event, context);
	struct socket_peer *p = container_of(ev, struct socket_peer, ev);
	struct ws_peer *ws_peer = container_of(p, struct ws_peer, s_peer);

	while (1) {
		const char *line_ptr;
		ssize_t line_length = read_cr_lf_line(p, &line_ptr);
		if (line_length > 0) {
			size_t nparsed = http_parser_execute(&ws_peer->parser, &ws_peer->parser_settings, line_ptr, line_length);
			if (nparsed != (size_t)line_length) {
				send_http_error_response(ws_peer, 400);
				p->peer.close(&p->peer);
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
				p->peer.close(&p->peer);
				return CONTINUE_LOOP;
			}
		}
	}

	p->ev.read_function = handle_ws_protocol;
	return handle_ws_protocol(loop, ctx);
}

static int ws_send_frame(struct peer *p, bool shall_mask, uint32_t mask, const char *payload, size_t length)
{
	struct socket_peer *s_peer = container_of(p, struct socket_peer, peer);
	struct ws_peer *ws_peer = container_of(s_peer, struct ws_peer, s_peer);

	char ws_header[14];
	uint8_t first_len;
	size_t header_index = 2;

	ws_header[0] = (uint8_t)(WS_TEXT_FRAME | WS_HEADER_FIN);
	if (length < 126) {
		first_len = (uint8_t)length;
	} else if (length < 65536) {
		uint16_t be_len = jet_htobe16((uint16_t)length);
		memcpy(&ws_header[2], &be_len, sizeof(be_len));
		header_index += sizeof(be_len);
		first_len = 126;
	} else {
		uint64_t be_len = jet_htobe64((uint64_t)length);
		memcpy(&ws_header[2], &be_len, sizeof(be_len));
		header_index += sizeof(be_len);
		first_len = 127;
	}

	if (shall_mask) {
		first_len |= WS_MASK_SET;
		memcpy(&ws_header[header_index], &mask, sizeof(mask));
		header_index += sizeof(mask);
	}
	ws_header[1] = first_len;

	return send_ws_response(ws_peer, ws_header, header_index, payload, length);
}

int ws_send_message(struct peer *p, const char *rendered, size_t len)
{
	return ws_send_frame(p, false, 0x00, rendered, len);
}

