#include <stdint.h>
#include <stdio.h>
#include <string.h>

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
		cJSON *method;
		const char *method_string;
		uint32_t parsed_length = end_parse - msg;
		if (unlikely(parsed_length != length)) {
			fprintf(stderr, "length of parsed JSON does not match message length!\n");
			return -1;
		}
		method = cJSON_GetObjectItem(root, "method");
		if (unlikely(method == NULL)) {
			goto no_method;
		}
		method_string = method->valuestring;
		if (unlikely(method_string == NULL)) {
			goto no_method;
		}

		if (strcmp(method_string, "set") == 0) {

		} else if (strcmp(method_string, "post") == 0) {

		} else if (strcmp(method_string, "add") == 0) {

		} else if (strcmp(method_string, "remove") == 0) {

		} else if (strcmp(method_string, "call") == 0) {

		} else if (strcmp(method_string, "fetch") == 0) {

		} else if (strcmp(method_string, "unfetch") == 0) {

		} else {
			fprintf(stderr, "Unsupported method: %s!\n", method_string);
			goto unsupported_method;
		}
		cJSON_Delete(root);
		return 0;

	no_method:
		fprintf(stderr, "Can not find supported method!\n");
	unsupported_method:
		cJSON_Delete(root);
		return -1;
	}
}
