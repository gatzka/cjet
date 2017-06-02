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

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MAIN
#define BOOST_TEST_MODULE utf8_checker_tests

#include <boost/test/unit_test.hpp>

#include "utf8_checker.h"

static const int invalid_message_size = 10;
static const uint8_t invalid_message[invalid_message_size][4] = {{0xC0,0x00,0x00,0x00},	//invalid start
																 {0xF6,0x00,0x00,0x00},	//invalid start
																 {0x80,0x00,0x00,0x00},	//invalid start
																 {0xC2,0x80,0x80,0x00},	//invalid continuation
																 {0xE0,0x60,0x80,0x00},	//invalid continuation
																 {0xE0,0x9F,0x80,0x00},	//reserved zone
																 {0xED,0xA0,0x80,0x00},	//reserved zone
																 {0xEF,0xA4,0x80,0x00},	//reserved zone
																 {0xF0,0x8F,0x80,0x80},	//reserved zone
																 {0xF4,0x90,0x80,0x80}};	//reserved zone

static const char valid_message[] = "Hello-µ@ßöäüàá-UTF-8!!";
static const uint8_t valid_message_long[] = {0xF1,0x80,0x80,0x80,0xF2,0xA0,0xA0,0xA0};

struct F {
	F ()
	{
		cjet_init_checker(&c);
	}

	~F()
	{
	}

	struct cjet_utf8_checker c;
};

/**
 * @brief tests the utf8 checker with a message of length 0
 */
BOOST_AUTO_TEST_CASE(test_message_zero_length)
{
	F f;
	char zero = '\0';
	int ret = cjet_is_text_valid(&f.c, &zero, 0);
	BOOST_CHECK_MESSAGE(ret == true, "Message should be valid!");
}

/**
 * @brief tests the utf8 checker with a valid message
 */
BOOST_AUTO_TEST_CASE(test_valid_message)
{
	F f;
	int ret = cjet_is_text_valid(&f.c, valid_message, sizeof(valid_message));
	BOOST_CHECK_MESSAGE(ret == true, "Message should be valid!");
}

/**
 * @brief tests the utf8 checker with a fragmented valid message
 *
 * The message is fragmented after an utf8 character, considering that
 * an utf8 character may consists of more than one byte.
 */
BOOST_AUTO_TEST_CASE(test_valid_message_fragmented_on_codepoints)
{
	F f;
	int ret = cjet_is_text_valid(&f.c, valid_message, 15);
	BOOST_CHECK_MESSAGE(ret == true, "Message should be valid!");
	ret = cjet_is_text_valid(&f.c, valid_message + 15, sizeof(valid_message) - 15);
	BOOST_CHECK_MESSAGE(ret == true, "Message should be valid!");
}

/**
 * @brief tests the utf8 checker with a fragmented valid message
 *
 * The message is fragmented after each byte. Hence some utf8 characters
 * are fragmented, too.
 */
BOOST_AUTO_TEST_CASE(test_valid_message_fragmented_between_letters)
{
	F f;
	int ret;
	for (uint i = 0; i < sizeof(valid_message); i++) {
		ret = cjet_is_text_valid(&f.c, valid_message + i, 1);
		BOOST_CHECK_MESSAGE(ret == true, "Message should be valid!");
	}
}

/**
 * @brief tests the utf8 checker with a valid message
 *
 * The message consists of two 4 byte utf8 characters
 */
BOOST_AUTO_TEST_CASE(test_valid_message_long)
{
	F f;
	int ret = cjet_is_byte_sequence_valid(&f.c, valid_message_long, sizeof(valid_message_long));
	BOOST_CHECK_MESSAGE(ret == true, "Message should be valid!");
}

/**
 * @brief tests the utf8 checker with a fragmented valid message
 *
 * The message consists of two 4 byte utf8 characters and is fragmented
 * between them.
 */
BOOST_AUTO_TEST_CASE(test_valid_message_fragmented_on_codepoints_long)
{
	F f;
	int ret = cjet_is_byte_sequence_valid(&f.c, valid_message_long, 4);
	BOOST_CHECK_MESSAGE(ret == true, "Message should be valid!");
	ret = cjet_is_byte_sequence_valid(&f.c, valid_message_long + 4, sizeof(valid_message_long) - 4);
	BOOST_CHECK_MESSAGE(ret == true, "Message should be valid!");
}

/**
 * @brief tests the utf8 checker with a fragmented valid message
 *
 * The message consists of two 4 byte utf8 characters. The message
 * is fragmented after each byte.
 */
BOOST_AUTO_TEST_CASE(test_valid_message_fragmented_between_letters_long)
{
	F f;
	int ret;
	for (uint i = 0; i < sizeof(valid_message_long); i++) {
		ret = cjet_is_byte_sequence_valid(&f.c, valid_message_long + i, 1);
		BOOST_CHECK_MESSAGE(ret == true, "Message should be valid!");
	}
}

/**
 * @brief tests the utf8 checker with a invalid message
 */
BOOST_AUTO_TEST_CASE(test_invalid_message)
{
	int ret;
	for (int i = 0; i < invalid_message_size; i++) {
		F f;
		ret = cjet_is_byte_sequence_valid(&f.c, invalid_message[i], sizeof(invalid_message[i]));
		BOOST_CHECK_MESSAGE(ret == false, "Message should be invalid!");
	}
}

/**
 * @brief tests the utf8 checker with a fragmented invalid message
 *
 * The message is fragmented after an utf8 character, considering that
 * an utf8 character may consists of more than one byte.
 */
BOOST_AUTO_TEST_CASE(test_invalid_message_fragmented_on_codepoints)
{
	F f;
	int ret = cjet_is_byte_sequence_valid(&f.c, valid_message_long, sizeof(valid_message_long));
	BOOST_CHECK_MESSAGE(ret == 1, "Message should be valid!");
	ret = cjet_is_byte_sequence_valid(&f.c, invalid_message[1], sizeof(invalid_message[1]));
	BOOST_CHECK_MESSAGE(ret == false, "Message should be invalid!");
}

/**
 * @brief tests the utf8 checker with a fragmented invalid message
 *
 * The message is fragmented after each byte. Hence some utf8 characters
 * are fragmented, too.
 */
BOOST_AUTO_TEST_CASE(test_invalid_message_fragmented_between_letters)
{
	int ret;
	for (int i = 0; i < invalid_message_size; i++) {
		F f;
		for (uint j = 0; j < sizeof(invalid_message[i]); j++) {
			ret = cjet_is_byte_sequence_valid(&f.c, &invalid_message[i][j], 1);
			if (ret < 1) break;
		}
		BOOST_CHECK_MESSAGE(ret == false, "Message should be invalid!");
	}
}