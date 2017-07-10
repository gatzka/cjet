/*
 *The MIT License (MIT)
 *
 * Copyright (c) <2017> <Felix Retsch>
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

#ifndef COMPRESSION_H
#define COMPRESSION_H

#include <stdbool.h>
#include <stdint.h>

#include "websocket.h"

#ifdef __cplusplus
extern "C" {
#endif

enum websocket_callback_return message_received_comp(bool is_compressed, struct websocket *s, char *msg, size_t length, enum websocket_callback_return(*message_received)(struct websocket *s, char *msg, size_t length));
enum websocket_callback_return frame_received_comp(bool is_compressed, struct websocket *s, char *msg, size_t length, bool is_last_frame, enum websocket_callback_return(*text_frame_received)(struct websocket *s, char *msg, size_t length, bool is_last_frame));
enum websocket_callback_return binary_received_comp(bool is_compressed, struct websocket *s, uint8_t *msg, size_t length, enum websocket_callback_return(*binary_received)(struct websocket *s, uint8_t *msg, size_t length));
enum websocket_callback_return binary_frame_received_comp(bool is_compressed, struct websocket *s, uint8_t *msg, size_t length, bool is_last_frame, enum websocket_callback_return(*binary_frame_received)(struct websocket *s, uint8_t *msg, size_t length, bool is_last_frame));
//enum websocket_callback_return ping_received_comp(struct websocket *s, uint8_t *msg, size_t length);
//enum websocket_callback_return pong_received_comp(struct websocket *s, uint8_t *msg, size_t length);
//enum websocket_callback_return close_received_comp(struct websocket *s, enum ws_status_code status_code);

int websocket_compress(const struct websocket *s, uint8_t *dest, uint8_t *src, size_t length);
//int websocket_send_binary_frame(const struct websocket *s, uint8_t *payload, size_t length);
//int websocket_send_close_frame(const struct websocket *s, enum ws_status_code status_code);
//int websocket_send_ping_frame(const struct websocket *s, uint8_t *payload, size_t length);
//int websocket_send_pong_frame(const struct websocket *s, uint8_t *payload, size_t length);

void alloc_compression(struct websocket *ws);
void free_compression(struct websocket *ws);
#ifdef __cplusplus
}
#endif

#endif
