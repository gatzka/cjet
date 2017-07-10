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

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "compression.h"
#include "log.h"
#include "zlib.h"

static void print_converted_ret(int err)
{
	switch (err) {
	case 0:
		log_info("Z_OK\n");
		break;
	case 1:
		log_info("Z_STREAM_END\n");
		break;
	case 2:
		log_warn("Z_NEED_DICT\n");
		break;
	case -1:
		log_err("Z_ERRNO\n");
		break;
	case -2:
		log_err("Z_STREAM_ERROR\n");
		break;
	case -3:
		log_err("Z_DATA_ERROR\n");
		break;
	case -4:
		log_err("Z_MEM_ERROR\n");
		break;
	case -5:
		log_err("Z_BUF_ERROR\n");
		break;
	case -6:
		log_err("Z_VERSION_ERROR\n");
		break;
	}
}

enum websocket_callback_return message_received_comp(bool is_compressed, struct websocket *s, char *msg, size_t length, enum websocket_callback_return(*text_message_received)(struct websocket *ws, char *txt, size_t len))
{
	if (is_compressed) {
		int ret;
		unsigned int have;
		z_stream *strm = &s->extension_compression.strm_decomp;

//		printf("inflate instream: ");
//		for (size_t i = 0; i < length; i++) {
//			printf ("0x%x ", (msg[i] & 0xFF));
//		}
//		printf("\n");

		strm->avail_in = length + 4;
		uint8_t in [length + 4];
		memcpy(in, msg, length);
		in[length] = 0x00;
		in[length + 1] = 0x00;
		in[length + 2] = 0xFF;
		in[length + 3] = 0xFF;
		strm->next_in = in;
		unsigned int size_out = 16 * length;
		strm->avail_out = size_out;
		uint8_t out[size_out];
		strm->next_out = out;
		ret = inflate(strm, Z_SYNC_FLUSH);
//		printf("inflate outstream: ");
//		for (size_t i = 0; i < (size_out - strm.avail_out); i++) {
//			printf ("0x%x ", (out[i] & 0xFF));
//		}
//		printf("\n");
		if (ret < Z_OK) {
			log_err("inflate error:");
			print_converted_ret(ret);
			inflateEnd(strm);
			return WS_ERROR;
		}
		have = size_out - strm->avail_out;
		return text_message_received(s, (char *)out, have);
	} else {
		return text_message_received(s, msg, length);
	}
}

static void write_int_to_array(uint8_t *array, unsigned int num)
{
	for (int i = 0; i < 4; i++) {
		array[i] = (num >> i * 8) & 0xFF;
	}
}

static unsigned int read_int_from_array(uint8_t *array)
{
	unsigned int ret = array[0] & 0xFF;
	ret |= (array[1] << 8) & 0xFF00;
	ret |= (array[2] << 16) & 0xFF0000;
	ret |= (array[3] << 24) & 0xFF000000;
	return ret;
}

enum websocket_callback_return frame_received_comp(bool is_compressed, struct websocket *s, char *msg, size_t length, bool is_last_frame, enum websocket_callback_return(*frame_received)(struct websocket *ws, char *txt, size_t len, bool is_last_frame))
{
	if (is_compressed) {
		z_stream *strm = &s->extension_compression.strm_decomp;

		/************************reasembling*********************************/
		if (length != 0) {
			if (strm->avail_in ==0) {
				unsigned int memory = length * 3 + 4;
				strm->next_in = malloc(memory);
				if (unlikely(strm->next_in == NULL)) {
					log_err("Inflate: Not enough memory for fragmented message!");
					strm->avail_in = 0;
					free(strm->next_in);
					return WS_ERROR;
				}
				strm->avail_in = memory - 4;
				write_int_to_array(strm->next_in, memory);
			}
			if (strm->avail_in <= length+ 4) {
				unsigned int next_size = read_int_from_array(strm->next_in) * 2;
				strm->next_in = realloc(strm->next_in, next_size);
				if (unlikely(strm->next_in == NULL)) {
					log_err("Inflate: Not enough memory for fragmented message!");
					strm->avail_in = 0;
					free(strm->next_in);
					return WS_ERROR;
				}
				strm->avail_in += next_size / 2;
				write_int_to_array(strm->next_in, next_size);
			}
			unsigned int write_offset = read_int_from_array(strm->next_in) - strm->avail_in;
			memcpy(strm->next_in + write_offset, msg, length);
			strm->avail_in -= length;
		}

		if (!is_last_frame) {
			return WS_OK;
		}


		/******************************decompression*******************************/
		int ret;
		unsigned int have;

//		printf("inflate instream: ");
//		for (size_t i = 0; i < length; i++) {
//			printf ("0x%x ", (msg[i] & 0xFF));
//		}
//		printf("\n");
		unsigned int sumLen = read_int_from_array(strm->next_in) - strm->avail_in - 4;
		memmove(strm->next_in, strm->next_in + 4, sumLen);
		strm->next_in[sumLen] = 0x00;
		strm->next_in[sumLen + 1] = 0x00;
		strm->next_in[sumLen + 2] = 0xFF;
		strm->next_in[sumLen + 3] = 0xFF;
		strm->avail_in = sumLen + 4;
		unsigned int size_out = 18 * sumLen;
		strm->avail_out = size_out;
		unsigned char out[size_out];
		strm->next_out = out;
		unsigned char in [strm->avail_in];
		memcpy(in, strm->next_in, strm->avail_in);
		free(strm->next_in);
		strm->next_in = in;
		ret = inflate(strm, Z_SYNC_FLUSH);
//		printf("inflate outstream: ");
//		for (size_t i = 0; i < (size_out - strm.avail_out); i++) {
//			printf ("0x%x ", (out[i] & 0xFF));
//		}
//		printf("\n");
		if (ret < Z_OK) {
			log_err("inflate error:");
			print_converted_ret(ret);
			inflateEnd(strm);
			free(strm->next_in);
			return WS_ERROR;
		}
		have = size_out - strm->avail_out;
		return frame_received(s, (char *)out, have, true);
	} else {
		return frame_received(s, msg, length, is_last_frame);
	}
}

enum websocket_callback_return binary_received_comp(bool is_compressed, struct websocket *s, uint8_t *msg, size_t length, enum websocket_callback_return(*binary_received)(struct websocket *s, uint8_t *msg, size_t length))
{
	if (is_compressed) {
		int ret;
		unsigned int have;
		z_stream *strm = &s->extension_compression.strm_decomp;

		strm->avail_in = length + 4;
		uint8_t in[length + 4];
		memcpy(in, msg, length);
		in[length] = 0x00;
		in[length + 1] = 0x00;
		in[length + 2] = 0xFF;
		in[length + 3] = 0xFF;
		strm->next_in = in;

		unsigned int size_out = 16 * length;
		strm->avail_out = size_out;
		uint8_t out[size_out];
		strm->next_out = out;
		ret = inflate(strm, Z_SYNC_FLUSH);
		if (ret < Z_OK) {
			log_err("inflate error:");
			print_converted_ret(ret);
			inflateEnd(strm);
			return WS_ERROR;
		}
		have = size_out - strm->avail_out;
		return binary_received(s, out, have);
	} else {
		return binary_received(s, msg, length);
	}
}

enum websocket_callback_return binary_frame_received_comp(bool is_compressed, struct websocket *s, uint8_t *msg, size_t length, bool is_last_frame, enum websocket_callback_return(*binary_frame_received)(struct websocket *s, uint8_t *msg, size_t length, bool is_last_frame))
{
	if (is_compressed) {
		z_stream *strm = &s->extension_compression.strm_decomp;

		/************************reasembling*********************************/
		if (length != 0) {
			if (strm->avail_in ==0) {
				unsigned int memory = length * 3 + 4;
				strm->next_in = malloc(memory);
				if (unlikely(strm->next_in == NULL)) {
					log_err("Inflate: Not enough memory for fragmented message!");
					strm->avail_in = 0;
					free(strm->next_in);
					return WS_ERROR;
				}
				strm->avail_in = memory - 4;
				write_int_to_array(strm->next_in, memory);
			}
			if (strm->avail_in <= length+ 4) {
				unsigned int next_size = read_int_from_array(strm->next_in) * 2;
				strm->next_in = realloc(strm->next_in, next_size);
				if (unlikely(strm->next_in == NULL)) {
					log_err("Inflate: Not enough memory for fragmented message!");
					strm->avail_in = 0;
					free(strm->next_in);
					return WS_ERROR;
				}
				strm->avail_in += next_size / 2;
				write_int_to_array(strm->next_in, next_size);
			}
			unsigned int write_offset = read_int_from_array(strm->next_in) - strm->avail_in;
			memcpy(strm->next_in + write_offset, msg, length);
			strm->avail_in -= length;
		}

		if (!is_last_frame) {
			return WS_OK;
		}


		/******************************decompression*******************************/
		int ret;
		unsigned int have;

		unsigned int sumLen = read_int_from_array(strm->next_in) - strm->avail_in - 4;
		memmove(strm->next_in, strm->next_in + 4, sumLen);
		strm->next_in[sumLen] = 0x00;
		strm->next_in[sumLen + 1] = 0x00;
		strm->next_in[sumLen + 2] = 0xFF;
		strm->next_in[sumLen + 3] = 0xFF;
		strm->avail_in = sumLen + 4;
		unsigned int size_out = 18 * sumLen;
		strm->avail_out = size_out;
		uint8_t out[size_out];
		strm->next_out = out;
//		strm->next_out = malloc(size_out);

		uint8_t in [strm->avail_in];
		memcpy(in, strm->next_in, strm->avail_in);
		free(strm->next_in);
		strm->next_in = in;
//		uint8_t *start_in = strm->next_in;

		ret = inflate(strm, Z_SYNC_FLUSH);
		if (ret < Z_OK) {
			log_err("inflate error:");
			print_converted_ret(ret);
			inflateEnd(strm);
			free(strm->next_in);
			free(strm->next_out);
			return WS_ERROR;
		}
		have = size_out - strm->avail_out;
		ret = binary_frame_received(s, strm->next_out, have, true);
//		free(strm->next_out);
//		free(start_in);
		return ret;
	} else {
		return binary_frame_received(s, msg, length, is_last_frame);
	}
}

int websocket_compress(const struct websocket *s,uint8_t *dest, uint8_t *src, size_t length)
{
	int ret;
	z_stream *strm = *(s->extension_compression.strm_comp);
	unsigned int have;

	strm->avail_in = length;
	strm->next_in = src;
	strm->avail_out = length * 2;
	strm->next_out = dest;
	ret = deflate(strm, Z_SYNC_FLUSH);
	if (ret < Z_OK) {
		log_err("deflate error: ");
		print_converted_ret(ret);
	}
	have = length * 2 - strm->avail_out;
	if (have < 4) log_err("Deflate not enough space!");

	if (dest[have - 1] != 0xff) log_err("Error remove tail deflate!");
	if (dest[have - 2] != 0xff) log_err("Error remove tail deflate!");
	if (dest[have - 3] != 0x00) log_err("Error remove tail deflate!");
	if (dest[have - 4] != 0x00) log_err("Error remove tail deflate!");
	have -= 4;

	if (ret < Z_OK) {
		log_err("deflate error %d\n",ret);
		deflateEnd(strm);
		return -1;
	}

	return have;
}
void alloc_compression(struct websocket *ws)
{
	int ret;
	z_stream *infl = &ws->extension_compression.strm_decomp;
	z_stream *defl = *(ws->extension_compression.strm_comp);

	infl->zalloc = Z_NULL;
	infl->zfree = Z_NULL;
	infl->opaque = Z_NULL;
	infl->avail_in = 0;
	infl->next_in = Z_NULL;
	ret = inflateInit(infl);
	if (ret != Z_OK) {
		inflateEnd(infl);
		log_err("inflateInit error %d\n",ret);
		return;
	}

	defl->zalloc = Z_NULL;
	defl->zfree = Z_NULL;
	defl->opaque = Z_NULL;
	ret = deflateInit(defl, 6);
	if (ret != Z_OK) {
		log_err("deflateInit error %d\n", ret);
		deflateEnd(defl);
		return;
	}
}

void free_compression(struct websocket *ws)
{
	deflateEnd(*ws->extension_compression.strm_comp);
	inflateEnd(&ws->extension_compression.strm_decomp);
}
