#include <stdint.h>
#include <stdio.h>

#include "compiler.h"
#include "cJSON.h"
#include "parse.h"

int parse_message(const char *msg, uint32_t length)
{
	cJSON *root;
	const char *end_parse;

	root = cJSON_ParseWithOpts(msg, &end_parse, 0);
	if (unlikely(root == NULL)) {
		fprintf(stderr, "Could not parse JSON!\n");
		return -1;
	} else {
		uint32_t parsed_length = end_parse - msg;
		if (unlikely(parsed_length != length)) {
			fprintf(stderr, "length of parsed JSON does not match to message length!\n");
			return -1;
		}
		cJSON_Delete(root);
		return 0;
	}
}
