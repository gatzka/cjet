/*
 * The MIT License (MIT)
 *
 * Copyright (c) <2016> <Stephan Gatzka>
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
#define BOOST_TEST_MODULE allocation

#include <boost/test/unit_test.hpp>
#include <stddef.h>

#include "alloc.h"
#include "generated/cjet_config.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

/*
 * Caution. Currently the allocation routines are not thread safe.
 * Therefore, all tests are performed in a single BOOST_AUTO_TEST_CASE
 * to let them run in a single thread.
 */
BOOST_AUTO_TEST_CASE(alloc)
{
	size_t alloc_size = CONFIG_MAX_HEAPSIZE_IN_KBYTE * 1024 - sizeof(size_t);
	void *ptr = cjet_malloc(alloc_size);
	BOOST_REQUIRE_MESSAGE(ptr != NULL, "Could not mallocate memory!");
	cjet_free(ptr);
	BOOST_CHECK_MESSAGE(cjet_get_alloc_size() == 0, "Allocated size did not went to 0 after free!");

	alloc_size = CONFIG_MAX_HEAPSIZE_IN_KBYTE * 1024 + 1;
	ptr = cjet_malloc(alloc_size);
	BOOST_REQUIRE_MESSAGE(ptr == NULL, "Could mallocate memory!");
	BOOST_CHECK_MESSAGE(cjet_get_alloc_size() == 0, "Allocated size not 0 after allocation failure!");

	alloc_size = CONFIG_MAX_HEAPSIZE_IN_KBYTE * 1024 - sizeof(size_t);
	ptr = cjet_calloc(1, alloc_size);
	BOOST_REQUIRE_MESSAGE(ptr != NULL, "Could not callocate memory!");
	cjet_free(ptr);
	BOOST_CHECK_MESSAGE(cjet_get_alloc_size() == 0, "Callocated size did not went to 0 after free!");

	alloc_size = CONFIG_MAX_HEAPSIZE_IN_KBYTE * 1024 + 1;
	ptr = cjet_calloc(1, alloc_size);
	BOOST_REQUIRE_MESSAGE(ptr == NULL, "Could callocate memory!");
	BOOST_CHECK_MESSAGE(cjet_get_alloc_size() == 0, "Callocated size not 0 after allocation failure!");
}
