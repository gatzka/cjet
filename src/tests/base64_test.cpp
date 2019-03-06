/*
 * The MIT License (MIT)
 *
 * Copyright (c) <2015> <Stephan Gatzka>
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
#define BOOST_TEST_MODULE base64

#include <boost/test/unit_test.hpp>
#include <cstring>
#include <stdint.h>

#define restrict

#include "base64.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

BOOST_AUTO_TEST_CASE(rfc4648_tests)
{

	static const char * const strings[] = { "", "f", "fo", "foo", "foob", "fooba", "foobar" };
	static const char * const results[] = { "", "Zg==", "Zm8=", "Zm9v", "Zm9vYg==", "Zm9vYmE=", "Zm9vYmFy" };

	size_t length = b64_encoded_buffer_length(std::strlen(strings[ARRAY_SIZE(strings)-1]));
	uint8_t result[length];

	for (unsigned int i = 0; i < ARRAY_SIZE(strings); ++i) {
		b64_encode_buffer(reinterpret_cast < const uint8_t * > (strings[i]), std::strlen(strings[i]), result);
		size_t length = b64_encoded_buffer_length(std::strlen(strings[i]));
		BOOST_CHECK_EQUAL(std::memcmp(results[i], result, length), 0);
		BOOST_CHECK_EQUAL(length, std::strlen(results[i]));
	}

	for (unsigned int i = 0; i < ARRAY_SIZE(strings); ++i) {
		size_t length = b64_encoded_buffer_length(std::strlen(strings[i]));
		BOOST_CHECK_EQUAL(std::strlen(results[i]), length);
	}
}

