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

#include "stdlib.h"
#include <string.h>

#include "base64.h"
#include "compiler.h"
#include "http_connection.h"
#include "jet_endian.h"
#include "jet_string.h"
#include "log.h"
#include "parse.h"
#include "sha1/sha1.h"
#include "websocket.h"

static const uint8_t WS_MASK_SET = 0x80;
static const uint8_t WS_HEADER_FIN = 0x80;

#ifndef ARRAY_SIZE
 #define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

#define CRLF "\r\n"

#define WS_CONTINUATION_FRAME 0x0
#define WS_TEXT_FRAME 0x1
#define WS_BINARY_FRAME 0x2
#define WS_CLOSE_FRAME 0x8
#define WS_PING_FRAME 0x9
#define WS_PONG_FRAME 0x0a

static void unmask_payload(char *buffer, uint8_t *mask, unsigned int length)
{
	for (unsigned int i= 0; i < length; i++) {
		buffer[i] = buffer[i] ^ (mask[i % 4]);
	}
}

static enum websocket_callback_return ws_handle_frame(struct websocket *s, char *msg, size_t length)
{
	switch (s->ws_flags.opcode) {
	case WS_CONTINUATION_FRAME:
		log_err("Fragmented websocket frame not supported!\n");
		return WS_ERROR;

	case WS_BINARY_FRAME:
		if (s->binary_message_received != NULL) {
			return s->binary_message_received(s, msg, length);
		}
		break;

	case WS_TEXT_FRAME:
		if (s->text_message_received != NULL) {
			return s->text_message_received(s, msg, length);
		}
		break;

	case WS_PING_FRAME:

		break;

	case WS_PONG_FRAME:
		if (s->pong_received != NULL) {
			return s->pong_received(s, msg, length);
		}

		break;

	case WS_CLOSE_FRAME:
		if (s->close_received != NULL) {
			uint16_t status_code = 0;
			if (length >= 2) {
				memcpy(&status_code, msg, sizeof(status_code));
				status_code = jet_be16toh(status_code);
				msg += sizeof(status_code);
				length -= sizeof(status_code);
			}
			return s->close_received(s, status_code, msg, length);
		}
		break;

	default:
		log_err("Unsupported websocket frame!\n");
		return WS_ERROR;
	}

	return WS_OK;
}

static enum bs_read_callback_return ws_get_header(void *context, char *buf, ssize_t len);

static enum bs_read_callback_return ws_get_payload(void *context, char *buf, ssize_t len)
{
	struct websocket *s = (struct websocket *)context;

	if (unlikely(len <= 0)) {
		if (len < 0) {
			log_err("Error while reading websocket payload!\n");
			if (s->on_error != NULL) {
				s->on_error(s);
			}
			return BS_CLOSED;
		}
		if (s->length != 0) {
			/*
			 * Other side closed the socket
			 */
			if (s->on_error != NULL) {
				s->on_error(s);
			}
			return BS_CLOSED;
		}
	}
	if (s->ws_flags.mask == 1) {
		unmask_payload(buf, s->mask, len);
		enum websocket_callback_return ret = ws_handle_frame(s, buf, len);
		switch (ret) {
		case WS_OK:
			buffered_socket_read_exactly(s->bs, 1, ws_get_header, s);
			return BS_OK;

		case WS_CLOSED:
			return BS_CLOSED;

		case WS_ERROR:
			if (s->on_error != NULL) {
				s->on_error(s);
			}
			return BS_CLOSED;
		}

	} // TODO: what if no mask set
	return BS_OK;
}

static enum bs_read_callback_return ws_get_mask(void *context, char *buf, ssize_t len)
{
	struct websocket *s = (struct websocket *)context;

	if (unlikely(len <= 0)) {
		if (len < 0) {
			log_err("Error while reading websocket mask!\n");
		}
		if (s->on_error != NULL) {
			s->on_error(s);
		}
		return BS_CLOSED;
	}

	memcpy(s->mask, buf, sizeof(s->mask));
	buffered_socket_read_exactly(s->bs, s->length, ws_get_payload, s);
	return BS_OK;
}

static void read_mask_or_payload(struct websocket *s)
{
	if (s->ws_flags.mask == 1) {
		buffered_socket_read_exactly(s->bs, sizeof(s->mask), ws_get_mask, s);
	} else {
		buffered_socket_read_exactly(s->bs, s->length, ws_get_payload, s);
	}
}

static enum bs_read_callback_return ws_get_length16(void *context, char *buf, ssize_t len)
{
	struct websocket *s = (struct websocket *)context;

	if (unlikely(len <= 0)) {
		if (len < 0) {
			log_err("Error while reading websocket 16 bit length!\n");
		}
		if (s->on_error != NULL) {
			s->on_error(s);
		}
		return BS_CLOSED;
	}

	uint16_t field;
	memcpy(&field, buf, sizeof(field));
	field = jet_be16toh(field);
	s->length = field;
	read_mask_or_payload(s);
	return BS_OK;
}

static enum bs_read_callback_return ws_get_length64(void *context, char *buf, ssize_t len)
{
	struct websocket *s = (struct websocket *)context;

	if (unlikely(len <= 0)) {
		if (len < 0) {
			log_err("Error while reading websocket 64 bit length!\n");
		}
		if (s->on_error != NULL) {
			s->on_error(s);
		}
		return BS_CLOSED;
	}

	uint64_t field;
	memcpy(&field, buf, sizeof(field));
	field = jet_be64toh(field);
	s->length = field;
	read_mask_or_payload(s);
	return BS_OK;
}

static enum bs_read_callback_return ws_get_first_length(void *context, char *buf, ssize_t len)
{
	struct websocket *s = (struct websocket *)context;

	if (unlikely(len <= 0)) {
		if (len < 0) {
			log_err("Error while reading websocket first length!\n");
		}
		if (s->on_error != NULL) {
			s->on_error(s);
		}
		return BS_CLOSED;
	}

	uint8_t field;
	memcpy(&field, buf, sizeof(field));
	if ((field & WS_MASK_SET) == WS_MASK_SET) {
		s->ws_flags.mask = 1;
	} else {
		s->ws_flags.mask = 0;
	}
	field = field & ~WS_MASK_SET;
	if (field < 126) {
		s->length = field;
		read_mask_or_payload(s);
	} else if (field == 126) {
		buffered_socket_read_exactly(s->bs, 2, ws_get_length16, s);
	} else {
		buffered_socket_read_exactly(s->bs, 8, ws_get_length64, s);
	}
	return BS_OK;
}

static enum bs_read_callback_return ws_get_header(void *context, char *buf, ssize_t len)
{
	struct websocket *s = (struct websocket *)context;

	if (unlikely(len <= 0)) {
		if (len < 0) {
			log_err("Error while reading websocket header!\n");
		}
		if (s->on_error != NULL) {
			s->on_error(s);
		}
		return BS_CLOSED;
	}

	uint8_t field;
	memcpy(&field, buf, sizeof(field));
	if ((field & WS_HEADER_FIN) == WS_HEADER_FIN) {
		s->ws_flags.fin = 1;
	} else {
		s->ws_flags.fin = 0;
	}

	static const uint8_t OPCODE_MASK = 0x0f;
	field = field & OPCODE_MASK;
	s->ws_flags.opcode = field;
	buffered_socket_read_exactly(s->bs, 1, ws_get_first_length, s);
	return BS_OK;
}

enum bs_read_callback_return websocket_read_header_line(void *context, char *buf, ssize_t len)
{
	struct websocket *s = (struct websocket *)context;

	if (unlikely(len <= 0)) {
		if (len < 0) {
			log_err("Error while reading header line!\n");
		}
		if (s->on_error != NULL) {
			s->on_error(s);
		}
		return BS_CLOSED;
	}

	size_t nparsed = http_parser_execute(&s->connection->parser, &s->connection->parser_settings, buf, len);
	if (unlikely(nparsed != (size_t)len)) {
		send_http_error_response(s->connection, 400);
		if (s->on_error != NULL) {
			s->on_error(s);
		}
		return BS_CLOSED;
	}
	if (s->connection->parser.upgrade) {
		/*
		 * Transfer ownership of buffered socket to websocket peer.
		 */
		s->bs = s->connection->bs;
		s->connection->bs = NULL;
		free_connection(s->connection);
		s->connection = NULL;
		buffered_socket_read_exactly(s->bs, 1, ws_get_header, s);
		return BS_OK;
	}

	buffered_socket_read_until(s->connection->bs, CRLF, websocket_read_header_line, s);
	return BS_OK;
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

static int send_upgrade_response(struct http_connection *connection)
{
	struct websocket *s = connection->parser.data;

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
	return buffered_socket_writev(connection->bs, iov, ARRAY_SIZE(iov));
}

int websocket_upgrade_on_header_field(http_parser *p, const char *at, size_t length)
{
	struct http_connection *connection = container_of(p, struct http_connection, parser);
	struct websocket *s = connection->parser.data;

	static const char sec_key[] = "Sec-WebSocket-Key";
	if ((sizeof(sec_key) - 1  == length) && (jet_strncasecmp(at, sec_key, length) == 0)) {
		s->current_header_field = HEADER_SEC_WEBSOCKET_KEY;
		return 0;
	}

	static const char ws_version[] = "Sec-WebSocket-Version";
	if ((sizeof(ws_version) - 1  == length) && (jet_strncasecmp(at, ws_version, length) == 0)) {
		s->current_header_field = HEADER_SEC_WEBSOCKET_VERSION;
		return 0;
	}

	static const char ws_protocol[] = "Sec-WebSocket-Protocol";
	if ((sizeof(ws_protocol) - 1  == length) && (jet_strncasecmp(at, ws_protocol, length) == 0)) {
		s->current_header_field = HEADER_SEC_WEBSOCKET_PROTOCOL;
		return 0;
	}

	return 0;
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

int websocket_upgrade_on_header_value(http_parser *p, const char *at, size_t length)
{
	int ret = 0;

	struct http_connection *connection = container_of(p, struct http_connection, parser);
	struct websocket *s = connection->parser.data;

	switch(s->current_header_field) {
	case HEADER_SEC_WEBSOCKET_KEY:
		ret = save_websocket_key(s->sec_web_socket_key, at, length);
		break;

	case HEADER_SEC_WEBSOCKET_VERSION:
		ret = check_websocket_version(at, length);
		break;

	case HEADER_SEC_WEBSOCKET_PROTOCOL:
		ret = check_websocket_protocol(at, length);
		break;

	case HEADER_UNKNOWN:
	default:
		break;
	}

	s->current_header_field = HEADER_UNKNOWN;
	return ret;
}
int websocket_upgrade_on_headers_complete(http_parser *parser)
{
	if (check_http_version(parser) < 0) {
		return -1;
	}
	if (parser->method != HTTP_GET) {
		return -1;
	}

	struct http_connection *connection = container_of(parser, struct http_connection, parser);
	if (!parser->upgrade) {
		return -1;
	}
	int ret = send_upgrade_response(connection);
	if (ret < 0) {
		return -1;
	} else {
		/*
		 * Returning "1" tells the http parser to skip the body of a message if there is one.
		 */
		return 1;
	}
}

static int send_frame(struct websocket *s, bool shall_mask, uint32_t mask, const char *payload, size_t length, unsigned int type)
{
	char ws_header[14];
	uint8_t first_len;
	size_t header_index = 2;

	ws_header[0] = (uint8_t)(type | WS_HEADER_FIN);
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

	struct buffered_socket_io_vector iov[2];
	iov[0].iov_base = ws_header;
	iov[0].iov_len = header_index;
	iov[1].iov_base = payload;
	iov[1].iov_len = length;
	return buffered_socket_writev(s->bs, iov, ARRAY_SIZE(iov));
}

int websocket_send_binary_frame(struct websocket *s, bool shall_mask, uint32_t mask, const char *payload, size_t length)
{
	return send_frame(s, shall_mask, mask, payload, length, WS_BINARY_FRAME);
}

int websocket_send_text_frame(struct websocket *s, bool shall_mask, uint32_t mask, const char *payload, size_t length)
{
	return send_frame(s, shall_mask, mask, payload, length, WS_TEXT_FRAME);
}

int websocket_sent_close_frame(struct websocket *s, bool shall_mask, uint32_t mask, uint16_t status_code, const char *payload, size_t length)
{
	char buffer[length + sizeof(status_code)];
	status_code = jet_htobe16(status_code);
	memcpy(buffer, &status_code, sizeof(status_code));
	memcpy(buffer + sizeof(status_code), payload, length);
	return send_frame(s, shall_mask, mask, buffer, length + sizeof(status_code), WS_CLOSE_FRAME);
}

void websocket_init(struct websocket *ws, struct http_connection *connection)
{
	ws->bs = NULL;
	ws->connection = connection;
	ws->current_header_field = HEADER_UNKNOWN;
	ws->text_message_received = NULL;
	ws->text_frame_received = NULL;
	ws->binary_message_received = NULL;
	ws->binary_frame_received = NULL;
	ws->pong_received = NULL;
	ws->close_received = NULL;
	ws->on_error = NULL;
}

void websocket_free(struct websocket *ws)
{
	if (ws->connection != NULL) {
		free_connection(ws->connection);
	}
	if (ws->bs != NULL) {
		websocket_sent_close_frame(ws, false, 0, 1001, NULL, 0);
		buffered_socket_close(ws->bs);
		free(ws->bs);
	}
}
