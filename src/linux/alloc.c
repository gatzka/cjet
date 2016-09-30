/*
 *The MIT License (MIT)
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

#include <stddef.h>
#include <stdlib.h>

#include "alloc.h"
#include "compiler.h"
#include "util.h"

struct memblock {
	size_t size;
	void *data;
};

void *cjet_malloc(size_t size)
{
	struct memblock *ptr = (struct memblock *)malloc(size + sizeof(size_t));
	if (unlikely(ptr == NULL)) {
		return NULL;
	}
	ptr->size = size;
	return &ptr->data;
}

void cjet_free(void *ptr)
{
	struct memblock *mem = container_of(ptr, struct memblock, data);
	free(mem);
}

void *cjet_calloc(size_t nmemb, size_t size)
{
	size_t bytes = nmemb * size + sizeof(size_t);
	struct memblock *ptr = calloc(1, bytes);
	if (unlikely(ptr == NULL)) {
		return NULL;
	}
	ptr->size = nmemb * size;
	return &ptr->data;
}
