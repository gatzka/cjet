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

#include "utf8_checker.h"


static int is_byte_valid(struct utf8_checker *c, uint8_t byte)
{
	int ret = 1;
	int finished = 0;
	switch (c->next_byte) {
	case 1:
		c->start_byte = byte;

		if (byte <= 0x7F) {
			finished = 1;
			ret = 1;
		} else if (byte <= 0xC1) {
			ret = 0;
		} else if (byte <= 0xDF) {
			c->length = 2;
			ret = 1;
		} else if (byte <= 0xEF) {
			c->length = 3;
			ret = 1;
		} else if (byte <= 0xF4) {
			c->length = 4;
			ret = 1;
		} else {
			ret = 0;
		}
		break;
	case 2:
		if ((byte & 0xC0) != 0x80) {
			ret = 0;
		}

		switch (c->start_byte) {
		case 0xE0:
			if ((byte < 0xA0) || (byte > 0xBF)) {
				ret = 0;
			}
			break;
		case 0xED:
			if ((byte < 0x80) || (byte > 0x9F)) {
				ret = 0;
			}
			break;
		case 0xEF:
			if ((byte < 0x80) || (byte > 0xA3)) {
				ret = 0;
			}
			break;
		case 0xF0:
			if ((byte < 0x90) || (byte > 0xBF)) {
				ret = 0;
			}
			break;
		case 0xF4:
			if ((byte < 0x80) || (byte > 0x8F)) {
				ret = 0;
			}
			break;
		}

		if (c->length == 2) finished = 1;
		break;
	case 3:
		if ((byte & 0xC0) != 0x80) {
			finished = 1;
			ret = 0;
		}
		if (c->length == 3) finished = 1;
		break;
	case 4:
		if ((byte & 0xC0) != 0x80) {
			ret = 0;
		}
		finished = 1;
		break;
	default:
		ret = -1;
		break;
	}
	if (finished || (ret < 1)) {
		c->start_byte = 0xFF;
		c->length = 1;
		c->next_byte = 1;
	} else {
		c->next_byte++;
	}
	return ret;
}

int is_text_valid(struct utf8_checker *c, char *text, size_t length)
{
	int ret = 1;
	for (unsigned int i = 0; i < length; i++) {
		ret = is_byte_valid(c, (uint8_t) *(text + i));
		if (ret == 0) return 0;
		if (ret == -1) return -1;
	}
	return ret;
}

int is_byte_sequence_valid(struct utf8_checker *c, uint8_t *sequence, size_t length)
{
	int ret = 1;
	for (unsigned int i = 0; i < length; i++) {
		ret = is_byte_valid(c, *(sequence + i));
		if (ret == 0) return 0;
		if (ret == -1) return -1;
	}
	return ret;
}

/*int is_text_valid(char *msg, size_t length)
{
	int ret = false;
	uint8_t tmp;
	for ( size_t i = 0; i < length; i++) {
		tmp = *(msg + i);
		if (tmp >= 0Xf5) {
			//unused code space
			return true;
		} else if (tmp <= 0x7f ) {
			//ASCII
		} else if (tmp <= 0xC1) {
			//would be ASCII in 2 byte or continuation byte
			return true;
		} else if (tmp <= 0xdf) {
			//2 byte
			i++;
			tmp = *(msg + i);
			if ((tmp & 0xc0) != 0x80) {
				return true;
			}
		} else if (tmp <= 0xef) {
			//3 byte
			uint8_t startbyte = tmp;
			i++;
			tmp = *(msg + i);
			if ((tmp & 0xc0) != 0x80) {
				return true;
			}
			if ((startbyte = 0xe0) && ((tmp < 0xA0) || (tmp > 0xbf))) {
				return true;
			}
			if ((startbyte = 0xed) && ((tmp < 0x80) || (tmp > 0x9f))) {
				return true;
			}
			i++;
			tmp = *(msg + i);
			if ((tmp & 0xc0) != 0x80) {
				return true;
			}
		} else {
			//4 byte
			uint8_t startbyte = tmp;
			i++;
			tmp = *(msg + i);
			if ((tmp & 0xc0) != 0x80) {
				return true;
			}
			if ((startbyte = 0xf0) && ((tmp < 0x90) || (tmp > 0xbf))) {
				return true;
			}
			if ((startbyte = 0xf4) && ((tmp < 0x80) || (tmp > 0x8f))) {
				return true;
			}
			for (int j = 0; j < 2; j++) {
				i++;
				tmp = *(msg + i);
				if ((tmp & 0xc0) != 0x80) {
					return true;
				}
			}
		}
	}
	return ret;
}*/

void init_checker(struct utf8_checker *c)
{
	c->start_byte = 0xFF;
	c->length = 1;
	c->next_byte = 1;
}
