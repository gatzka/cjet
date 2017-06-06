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

#include "utf8_checker.h"

#define UC_FINISH 0xFF

static bool is_byte_valid(struct cjet_utf8_checker *c, uint8_t byte)
{
	bool ret = true;
	int finished = 0;
	switch (c->next_byte) {
	case 1:
		c->start_byte = byte;

		if (byte <= 0x7F) {
			finished = 1;
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
		case 0xEF:
			if ((byte < 0x80) || (byte > 0xA3)) {
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

		if (c->length == 2) finished = 1;
		break;
	case 3:
		if ((byte & 0xC0) != 0x80) {
			finished = 1;
			ret = false;
		}
		if (c->length == 3) finished = 1;
		break;
	case 4:
		if ((byte & 0xC0) != 0x80) {
			ret = false;
		}
		finished = 1;
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

bool cjet_is_text_valid(struct cjet_utf8_checker *c, const char *text, size_t length, bool is_complete)
{
	bool ret = true;
	for (unsigned int i = 0; i < length; i++) {
		ret = is_byte_valid(c, (uint8_t) *(text + i));
		if (ret == false) return false;
	}
	if (is_complete) {
		if (c->start_byte != UC_FINISH) return false;
	}
	return ret;
}

bool cjet_is_byte_sequence_valid(struct cjet_utf8_checker *c, const uint8_t *sequence, size_t length, bool is_complete)
{
	bool ret = true;
	for (unsigned int i = 0; i < length; i++) {
		ret = is_byte_valid(c, *(sequence + i));
		if (ret == false) return false;
	}
	if (is_complete) {
		if (c->start_byte != UC_FINISH) return false;
	}
	return ret;
}

void cjet_init_checker(struct cjet_utf8_checker *c)
{
	c->start_byte = UC_FINISH;
	c->length = 1;
	c->next_byte = 1;
}
