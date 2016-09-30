/*
 *The MIT License (MIT)
 *
 * Copyright (c) <2014> <Stephan Gatzka>
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
#include <string.h>

#include "alloc.h"
#include "compiler.h"
#include "jet_string.h"

char *duplicate_string(const char *s)
{
	char *ptr = cjet_malloc(strlen(s) + 1);
	if (unlikely(ptr == NULL)) {
		return NULL;
	}
	strcpy(ptr, s);
	return ptr;
}

const char *jet_strcasestr(const char *haystack, const char *needle)
{
	return strcasestr(haystack, needle);
}

int jet_strcasecmp(const char *s1, const char *s2)
{
	return strcasecmp(s1, s2);
}

int jet_strncasecmp(const char *s1, const char *s2, size_t n)
{
	return strncasecmp(s1, s2, n);
}

void *jet_memmem(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen)
{
	return memmem(haystack, haystacklen, needle, needlelen);
}
