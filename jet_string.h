#ifndef CJET_STRING_H
#define CJET_STRING_H

#include <stdlib.h>
#include <string.h>

static inline char *duplicate_string(const char *s)
{
	size_t length = strlen(s);
	char *new_string = malloc(length + 1);
	if (unlikely(new_string == NULL)) {
		return NULL;
	}
	strncpy(new_string, s, length + 1);
	return new_string;
}

#endif
