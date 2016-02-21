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

#include "base64.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

BOOST_AUTO_TEST_CASE(rfc4648_tests)
{

	static const char * const strings[] = { "", "f", "fo", "foo", "foob", "fooba", "foobar" };
	static const char * const results[] = { "", "Zg==", "Zm8=", "Zm9v", "Zm9vYg==", "Zm9vYmE=", "Zm9vYmFy" };

	char result[b64_encoded_string_length(std::strlen(strings[ARRAY_SIZE(strings) -1]))];

	for (unsigned int i = 0; i < ARRAY_SIZE(strings); ++i) {
		b64_encode_string(strings[i], std::strlen(strings[i]), result);
		BOOST_CHECK_EQUAL(std::strcmp(results[i], result), 0);
	}
}

