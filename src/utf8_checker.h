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

#ifndef CJET_UTF8_CHECKER_H
#define CJET_UTF8_CHECKER_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @brief This file contains the interface of a utf8 checker.
 *
 * The checker can be used to check, if a char or byte sequence
 * consists only of valid utf8. It is possible to check
 * fragmented sequences, too.
 */

/**
 * @brief The cjet_utf8_checker struct.
 *
 * Holds the state of a checker instance. Do not change the
 * values of the attributes.
 */
struct cjet_utf8_checker {
	/**
	 * @privatesection
	 */
	uint8_t start_byte;
	uint8_t length;
	uint8_t next_byte;
};

/**
 * @brief The type of a utf8 checker initialization function.
 *
 * initializes the given utf8 checker. Must be called only once before
 * the first use of the validation functions.
 *
 * @param c a utf8 checker to be initialized
 */
void cjet_init_checker(struct cjet_utf8_checker *c);

/**
 * @brief The type of a byte sequence validation function
 *
 * validates a given byte sequence with a given length. If an invalid utf8 character
 * occurs, the validation is stopped and false is returned.
 *
 * @param c an utf8 checker, should be initialized
 * @param sequence the byte sequence to be checked
 * @param length the length of the byte sequence
 * @param is_complete true, if the sequence is complete or last fragment,
 *						false otherwise
 *
 * @return true if the byte sequence consists only of valid utf8 characters,
 *			false otherwise
 */
bool cjet_is_byte_sequence_valid(struct cjet_utf8_checker *c, const uint8_t *sequence, size_t length, bool is_complete);

bool cjet_is_word_sequence_valid(struct cjet_utf8_checker *c, const uint32_t *sequence, size_t length, bool is_complete);

bool cjet_is_word64_sequence_valid(struct cjet_utf8_checker *c, const uint64_t *sequence, size_t length, bool is_complete);

/**
 * @brief The type of a text validation function
 *
 * validates a given char sequence with a given length. If an invalid utf8 character
 * occurs, the validation is stopped and false is returned.
 *
 * @param c an utf8 checker, should be initialized
 * @param text the char sequence to be checked
 * @param length the length of the char sequence
 * @param is_complete true, if the sequence is complete or last fragment,
 *						false otherwise
 *
 * @return true if the text consists only of valid utf8 characters,
 *			false otherwise
 */
bool cjet_is_text_valid(struct cjet_utf8_checker *c, const char *text, size_t length, bool is_complete);

/**
 * @brief The type of a text validation function
 *
 * validates a given char, byte or word sequence with a given length in bytes. If an invalid utf8 character
 * occurs, the validation is stopped and false is returned. It analayses the size of uint_fast and chooses
 * a suitable allinged word validation. The word sequence must be stored as Big Endian (Network Byteorder).
 *
 * @param c an utf8 checker, should be initialized
 * @param sequence the text sequence to be checked
 * @param byte_length the lenght of the sequence in byte
 * @param is_complete true, if the sequence is complete or last fragment,
 *						false otherwise
 *
 * @return true if the text consists only of valid utf8 characters,
 *			false otherwise
 */
bool cjet_is_word_sequence_valid_auto_alligned(struct cjet_utf8_checker *c, const void *sequence, size_t byte_length, bool is_complete);

#ifdef __cplusplus
}
#endif

#endif
