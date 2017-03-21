/*
*The MIT License (MIT)
*
* Copyright (c) <2017> <Stephan Gatzka>
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

#include <ctype.h>
#include <stddef.h>
#include <string.h>

#include "jet_string.h"

void *jet_memmem(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen)
{
	register char *cur, *last;
	const char *cl = (const char *)haystack;
	const char *cs = (const char *)needle;

	if (haystacklen == 0 || needlelen == 0)
		return NULL;

	if (haystacklen < needlelen)
		return NULL;

	if (needlelen == 1)
		return memchr(haystack, (int)*cs, haystacklen);

	last = (char *)cl + haystacklen - needlelen;

	for (cur = (char *)cl; cur <= last; cur++)
		if (cur[0] == cs[0] && memcmp(cur, cs, needlelen) == 0)
			return cur;

	return NULL;
}

const char *jet_strcasestr(const char *haystack, const char *needle)
{
	char c, sc;
	size_t len;

	if ((c = *needle++) != 0) {
		c = tolower((unsigned char)c);
		len = strlen(needle);
		do {
			do {
				if ((sc = *haystack++) == 0)
					return (NULL);
			} while ((char)tolower((unsigned char)sc) != c);
		} while (jet_strncasecmp(haystack, needle, len) != 0);
		haystack--;
	}
	return (haystack);
}

int jet_strncasecmp(const char *s1, const char *s2, size_t n)
{
	return _strnicmp(s1, s2, n);
}

int jet_strcasecmp(const char *s1, const char *s2)
{
	return _stricmp(s1, s2);
}
