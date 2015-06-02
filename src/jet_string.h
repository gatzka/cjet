#ifndef CJET_STRING_H
#define CJET_STRING_H

#include <stdlib.h>
#include <string.h>

static inline char *duplicate_string(const char *s)
{
	size_t length = strlen(s);
	char *new_string = malloc(length + 1);
	if (likely(new_string != NULL)) {
		strncpy(new_string, s, length + 1);
	}
	return new_string;
}

static inline char *jet_strcasestr(const char *haystack, const char *needle)
{
	size_t hay_len = strlen(haystack);
	size_t needle_len = strlen(needle);
	while (hay_len >= needle_len) {
		if (strncasecmp(haystack, needle, needle_len) == 0)
		    return (char *) haystack;

		haystack++;
		hay_len--;
	}

	return NULL;
}

#endif
