/*
 * The MIT License (MIT)
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
#include <stdint.h>
#include <stdio.h>

#include "utf8_checker.h"

const uint8_t UC_FINISH = 0xFF;
const unsigned int FAST_ZONE1 = 0x80808080;
const unsigned int FAST_ZONE21 = 0x8080C0E0;
const unsigned int FAST_ZONE22 = 0x80C0E080;
const unsigned int FAST_ZONE23 = 0xC0E08080;
const unsigned int FAST_ZONE24 = 0xC0E0C0E0;
const uint64_t FAST_ZONE1_64 = 0x8080808080808080;
const uint64_t FAST_ZONE2_64 = 0xC0E0C0E0C0E0C0E0;

static bool is_byte_valid(struct cjet_utf8_checker *restrict c, uint8_t byte)
{
	bool ret = true;
	bool finished = false;
	switch (c->next_byte) {
	case 1:
		c->start_byte = byte;

		if (byte <= 0x7F) {
			finished = true;
			ret = true;
		} else if (byte <= 0xC1) {
			ret = false;
		} else if (byte <= 0xDF) {
			c->length = 2;
			ret = true;
		} else if (byte <= 0xEF) {
			c->length = 3;
			ret = true;
		} else if (byte <= 0xF4) {
			c->length = 4;
			ret = true;
		} else {
			ret = false;
		}
		break;
	case 2:
		if ((byte & 0xC0) != 0x80) {
			ret = false;
		}

		switch (c->start_byte) {
		case 0xE0:
			if ((byte < 0xA0) || (byte > 0xBF)) {
				ret = false;
			}
			break;
		case 0xED:
			if ((byte < 0x80) || (byte > 0x9F)) {
				ret = false;
			}
			break;
		case 0xF0:
			if ((byte < 0x90) || (byte > 0xBF)) {
				ret = false;
			}
			break;
		case 0xF4:
			if ((byte < 0x80) || (byte > 0x8F)) {
				ret = false;
			}
			break;
		}

		if (c->length == 2) finished = true;
		break;
	case 3:
		if ((byte & 0xC0) != 0x80) {
			finished = true;
			ret = false;
		}
		if (c->length == 3) finished = true;
		break;
	case 4:
		if ((byte & 0xC0) != 0x80) {
			ret = false;
		}
		finished = true;
		break;
	default:
		ret = false;
		break;
	}
	if (finished || (ret < 1)) {
		c->start_byte = UC_FINISH;
		c->length = 1;
		c->next_byte = 1;
	} else {
		c->next_byte++;
	}
	return ret;
}

bool cjet_is_text_valid(struct cjet_utf8_checker *restrict c, const char *restrict text, size_t length, bool is_complete)
{
	bool ret = true;
	for (size_t i = 0; i < length; i++) {
		ret = is_byte_valid(c, (uint8_t) *(text + i));
		if (ret == false) return false;
	}
	if (is_complete) {
		if (c->start_byte != UC_FINISH) return false;
	}
	return ret;
}

bool cjet_is_byte_sequence_valid(struct cjet_utf8_checker *restrict c, const uint8_t *restrict sequence, size_t length, bool is_complete)
{
	bool ret = true;
	for (size_t i = 0; i < length; i++) {
		ret = is_byte_valid(c, *(sequence + i));
		if (ret == false) return false;
	}
	if (is_complete) {
		if (c->start_byte != UC_FINISH) {
			cjet_init_checker(c);
			return false;
		}
	}
	return ret;
}

bool cjet_is_word_sequence_valid(struct cjet_utf8_checker *restrict c, const unsigned int *sequence, size_t length, bool is_complete)
{
	bool ret = true;
	unsigned int tmp = 0x0;
	for (size_t i = 0; i < length; i++) {
		tmp = *(sequence + i);
		if (c->next_byte == 1) {
			if (!(tmp & FAST_ZONE1)) continue;
			if (((tmp & FAST_ZONE21) == 0x80C0) && ((tmp & 0x1F) > 0x01)) continue;
			if (((tmp & FAST_ZONE22) == 0x80C000) && ((tmp & 0x1F00) > 0x0100)) continue;
			if (((tmp & FAST_ZONE23) == 0x80C00000) && ((tmp & 0x1F0000) > 0x010000)) continue;
			if (((tmp & FAST_ZONE24) == 0x80C080C0) && ((tmp & 0x1F001F) > 0x010001)) continue;
		}
		for (int j = 0; j < 4; j++) {
			tmp = *(sequence + i);
			tmp = tmp >> j * 8;
			tmp &= 0xFF;
			ret = is_byte_valid(c, (uint8_t) tmp);
			if (ret == false) return false;
		}
	}
	if (is_complete) {
		if (c->start_byte != UC_FINISH) {
			cjet_init_checker(c);
			return false;
		}
	}
	return ret;
}

bool cjet_is_word64_sequence_valid(struct cjet_utf8_checker *restrict c, const uint64_t *sequence, size_t length, bool is_complete)
{
	bool ret = true;
	uint64_t tmp = 0x0;
	for (size_t i = 0; i < length; i++) {
		tmp = *(sequence + i);
		if (c->next_byte == 1) {
			if (!(tmp & FAST_ZONE1_64)) continue;
			if(((tmp & FAST_ZONE2_64) == 0x80C080C080C080C0) && ((tmp & 0x001F001F001F001F) > 0x0001000100010001)) continue;
		}
		for (int j = 0; j <8; j++) {
			tmp = *(sequence + i);
			tmp >>= (j * 8);
			tmp &= 0xFF;
			ret = is_byte_valid(c, (uint8_t) tmp);
			if (ret == false) return false;
		}
	}
	if (is_complete) {
		if (c->start_byte != UC_FINISH) {
			cjet_init_checker(c);
			return false;
		}
	}
	return ret;
}

bool cjet_is_word_sequence_valid_auto_alligned(struct cjet_utf8_checker *restrict c, const void *sequence, size_t byte_length, bool is_complete)
{
	size_t bytewidth = sizeof(uint_fast16_t);
	if (byte_length < 8) bytewidth = 1;
	printf("bytewidth %zu\n",bytewidth);
	size_t pre_length, main_length, post_length;
	int ret;
	const uint8_t* ptr_alligned = sequence;
	switch (bytewidth) {
	case 8:
		pre_length = ((uint64_t) sequence) % 8;
		main_length = (byte_length - pre_length) >> 3;
		post_length = byte_length - pre_length - ( main_length << 3);
		ret = cjet_is_byte_sequence_valid(c, ((const uint8_t*) sequence), pre_length, 0);
		ptr_alligned += pre_length;
		ret &= cjet_is_word64_sequence_valid(c, ((const uint64_t*) ptr_alligned), main_length, 0);
		ret &= cjet_is_byte_sequence_valid(c, ((const uint8_t*) sequence) + pre_length + (main_length << 3), post_length, 0);
		break;
	case 4:
		pre_length = ((uint64_t) sequence) % 4;
		main_length = (byte_length - pre_length) >> 2;
		post_length = byte_length - pre_length - ( main_length << 2);
		ret = cjet_is_byte_sequence_valid(c, ((const uint8_t*) sequence), pre_length, 0);
		ptr_alligned += pre_length;
		ret &= cjet_is_word_sequence_valid(c, ((const unsigned int*) ptr_alligned), main_length, 0);
		ret &= cjet_is_byte_sequence_valid(c, ((const uint8_t*) sequence) + pre_length + (main_length << 2), post_length, 0);
		break;
	default:
		ret = cjet_is_byte_sequence_valid(c, sequence, byte_length, is_complete);
		break;
	}
	if (is_complete) {
		if (c->start_byte != UC_FINISH) {
			cjet_init_checker(c);
			return false;
		}
	}
	return ret;
}

void cjet_init_checker(struct cjet_utf8_checker *c)
{
	c->start_byte = UC_FINISH;
	c->length = 1;
	c->next_byte = 1;
}
