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

static int reassemble(struct websocket *s, uint8_t *msg, size_t length)
{
	if (length != 0) {
		z_stream *strm = &s->extension_compression.strm_decomp;
		if (strm->avail_in == 0) {
			unsigned int memory = length * 3 + 4;
			strm->next_in = malloc(memory);
			if (unlikely(strm->next_in == NULL)) {
				log_err("Reassemble: Not enough memory for alloc!");
				strm->avail_in = 0;
				free(strm->next_in);
				return -1;
			}
			strm->avail_in = memory - 4;
			write_int_to_array(strm->next_in, memory);
		}
		if (strm->avail_in <= length + 4) {
			unsigned int next_size = read_int_from_array(strm->next_in) * 2;
			strm->next_in = realloc(strm->next_in, next_size);
			if (unlikely(strm->next_in == NULL)) {
				log_err("Reassemble: Not enough memory for realloc!");
				strm->avail_in = 0;
				free(strm->next_in);
				return -1;
			}
			strm->avail_in += next_size / 2;
			write_int_to_array(strm->next_in, next_size);
		}
		unsigned int write_offset = read_int_from_array(strm->next_in) - strm->avail_in;
		memcpy(strm->next_in + write_offset, msg, length);
		strm->avail_in -= length;
	}
	return 0;
}

static enum websocket_callback_return private_decompress(struct websocket *s, uint8_t *msg, size_t length, uint8_t **free_ptr, size_t *have)
{
	int ret;
	z_stream *strm = &s->extension_compression.strm_decomp;

	strm->avail_in = length + 4;
	uint8_t *in = malloc(length + 4);
	if (in == NULL) {
		log_err("inflate in error: malloc");
		return WS_ERROR;
	}
	memcpy(in, msg, length);
	in[length] = 0x00;
	in[length + 1] = 0x00;
	in[length + 2] = 0xFF;
	in[length + 3] = 0xFF;
	strm->next_in = in;

	size_t size_out = 20 * length;
	strm->avail_out = size_out;
	*free_ptr = malloc(size_out);
	if (*free_ptr == NULL) {
		log_err("inflate out error: malloc");
		return WS_ERROR;
	}
	uint8_t *out = *free_ptr;
	strm->next_out = out;
	do {
		if (strm->avail_out == 0) {
			strm->avail_out += size_out;
			size_out *= 2;
			*free_ptr = realloc(*free_ptr, size_out);
			if (*free_ptr == NULL) {
				log_err("inflate out error: realloc");
				return WS_ERROR;
			}
			out = *free_ptr;
			strm->next_out = out + size_out / 2;
		}
		if (s->extension_compression.client_no_context_takeover) {
			ret = inflate(strm, Z_FINISH);
		} else {
			ret = inflate(strm, Z_SYNC_FLUSH);
		}
		if (ret < Z_OK && ret != Z_BUF_ERROR) {
			log_err("inflate error:");
			print_converted_ret(ret);
			inflateEnd(strm);
			return WS_ERROR;
		}
	}while(strm->avail_out == 0);
	free(in);
	if (strm->avail_in != 0) {
		log_err("Shit happens! Not all data is decompressed");
		return WS_ERROR;
	}
	*have = size_out - strm->avail_out;
	return WS_OK;
}

enum websocket_callback_return text_received_comp(bool is_compressed, struct websocket *s, char *msg, size_t length,
                               enum websocket_callback_return(*text_message_received)(struct websocket *ws, char *txt, size_t len))
{
	if (is_compressed && (s->extension_compression.compression_level != 0)) {
		enum websocket_callback_return ret;
		size_t have = 0;
		uint8_t *free_ptr = NULL;
		ret = private_decompress(s, (uint8_t *)msg, length, &free_ptr, &have);
		if (ret == WS_ERROR) return ret;
		ret = text_message_received(s, (char *)free_ptr, have);
		free(free_ptr);
		return ret;
	} else {
		return text_message_received(s, msg, length);
	}
}

enum websocket_callback_return text_frame_received_comp(bool is_compressed, struct websocket *s, char *msg, size_t length, bool is_last_frame,
                               enum websocket_callback_return(*text_frame_received)(struct websocket *ws, char *txt, size_t len, bool is_last_frame))
{
	if (is_compressed && (s->extension_compression.compression_level != 0)) {
		z_stream *strm = &s->extension_compression.strm_decomp;

		int ret_val = reassemble(s, (uint8_t *)msg, length);
		if (ret_val < 0) return WS_ERROR;
		if (!is_last_frame) {
			return WS_OK;
		}

		enum websocket_callback_return ret;
		size_t have = 0;
		uint8_t *free_ptr = NULL;
		uint8_t *in_ptr = strm->next_in;
		size_t sumLen = read_int_from_array(strm->next_in) - strm->avail_in - 4;
		memmove(strm->next_in, strm->next_in + 4, sumLen);

		ret = private_decompress(s, strm->next_in, sumLen, &free_ptr, &have);
		if (ret == WS_ERROR) return ret;
		ret = text_frame_received(s,(char *) free_ptr, have, is_last_frame);
		free(in_ptr);
		free(free_ptr);
		return ret;
	} else {
		return text_frame_received(s, msg, length, is_last_frame);
	}
}

enum websocket_callback_return binary_received_comp(bool is_compressed, struct websocket *s, uint8_t *msg, size_t length,
                               enum websocket_callback_return(*binary_message_received)(struct websocket *s, uint8_t *msg, size_t length))
{
	if (is_compressed && (s->extension_compression.compression_level != 0)) {
		enum websocket_callback_return ret;
		size_t have = 0;
		uint8_t *free_ptr = NULL;
		ret = private_decompress(s, msg, length, &free_ptr, &have);
		if (ret == WS_ERROR) return ret;
		ret = binary_message_received(s, free_ptr, have);
		free(free_ptr);
		return ret;
	} else {
		return binary_message_received(s, msg, length);
	}
}

enum websocket_callback_return binary_frame_received_comp(bool is_compressed, struct websocket *s, uint8_t *msg, size_t length, bool is_last_frame,
                               enum websocket_callback_return(*binary_frame_received)(struct websocket *s, uint8_t *msg, size_t length, bool is_last_frame))
{
	if (is_compressed && (s->extension_compression.compression_level != 0)) {
		z_stream *strm = &s->extension_compression.strm_decomp;

		int ret_val = reassemble(s, msg, length);
		if (ret_val < 0) return WS_ERROR;
		if (!is_last_frame) {
			return WS_OK;
		}

		enum websocket_callback_return ret;
		size_t have = 0;
		uint8_t *free_ptr = NULL;
		uint8_t *in_ptr = strm->next_in;
		size_t sumLen = read_int_from_array(strm->next_in) - strm->avail_in - 4;
		memmove(strm->next_in, strm->next_in + 4, sumLen);
		ret = private_decompress(s, strm->next_in, sumLen, &free_ptr, &have);
		if (ret == WS_ERROR) return ret;
		ret = binary_frame_received(s, free_ptr, have, is_last_frame);
		free(in_ptr);
		free(free_ptr);
		return ret;
	} else {
		return binary_frame_received(s, msg, length, is_last_frame);
	}
}

int websocket_compress(const struct websocket *s, uint8_t *dest, uint8_t *src, size_t length)
{
	if (s->extension_compression.compression_level == 0) {
		memcpy(dest, src, length);
		return length;
	}
	int ret;
	z_stream *strm = *(s->extension_compression.strm_comp);
	unsigned int have;

	strm->avail_in = length;
	strm->next_in = src;
	strm->avail_out = length * 2;
	strm->next_out = dest;
	if (s->extension_compression.server_no_context_takeover) {
		ret = deflate(strm, Z_FULL_FLUSH);
	} else {
		ret = deflate(strm, Z_SYNC_FLUSH);
	}
	if (ret < Z_OK) {
		log_err("deflate error: ");
		print_converted_ret(ret);
		deflateEnd(strm);
		return -1;
	}
	have = length * 2 - strm->avail_out;
	if (have < 4) log_err("Deflate not enough space!");

	if (dest[have - 1] != 0xff) log_err("Error remove tail deflate!");
	if (dest[have - 2] != 0xff) log_err("Error remove tail deflate!");
	if (dest[have - 3] != 0x00) log_err("Error remove tail deflate!");
	if (dest[have - 4] != 0x00) log_err("Error remove tail deflate!");
	have -= 4;
	return have;
}
void alloc_compression(struct websocket *ws)
{
	if (ws->extension_compression.compression_level == 0) return;
	int ret;
	z_stream *infl = &ws->extension_compression.strm_decomp;
	z_stream *defl = *(ws->extension_compression.strm_comp);

	infl->zalloc = Z_NULL;
	infl->zfree = Z_NULL;
	infl->opaque = Z_NULL;
	infl->avail_in = 0;
	infl->next_in = Z_NULL;
	int max_win_bits = -(ws->extension_compression.client_max_window_bits);
	ret = inflateInit2(infl, max_win_bits);
	if (ret != Z_OK) {
		inflateEnd(infl);
		log_err("inflateInit error %d",ret);
		print_converted_ret(ret);
		return;
	}

	defl->zalloc = Z_NULL;
	defl->zfree = Z_NULL;
	defl->opaque = Z_NULL;
	int comp_level, mem_level;
	switch (ws->extension_compression.compression_level) {
	case 1:
		comp_level = Z_BEST_SPEED;
		mem_level = 1;
		break;
	case 3:
		comp_level = Z_BEST_COMPRESSION;
		mem_level = 9;
		break;
	default:
		comp_level = Z_DEFAULT_COMPRESSION;
		mem_level = 8;
		break;
	}
	if (ws->extension_compression.server_max_window_bits == 8) {
		log_warn("zlib currently not support a window size of 8 for deflate\n! "
		         "Switching to size 9.");
		ws->extension_compression.server_max_window_bits = 9;
	}
	max_win_bits =  -(ws->extension_compression.server_max_window_bits);
	ret = deflateInit2(defl, comp_level, Z_DEFLATED, max_win_bits, mem_level, Z_DEFAULT_STRATEGY);
	if (ret != Z_OK) {
		log_err("deflateInit error %d", ret);
		print_converted_ret(ret);
		deflateEnd(defl);
		return;
	}
}

void free_compression(struct websocket *ws)
{
	if (ws->extension_compression.compression_level == 0) return;
	deflateEnd(*ws->extension_compression.strm_comp);
	inflateEnd(&ws->extension_compression.strm_decomp);
}
