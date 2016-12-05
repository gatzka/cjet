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

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "groups.h"
#include "log.h"

static cJSON *all_groups;

static bool is_in_groups(const char *group_name)
{
	unsigned int number_of_groups = cJSON_GetArraySize(all_groups);
	for (unsigned int i = 0; i < number_of_groups; ++i) {
		const cJSON *group = cJSON_GetArrayItem(all_groups, i);
		if (strcmp(group->valuestring, group_name) == 0) {
			return true;
		}
	}

	return false;
}

static int add_group(const char *group_name)
{
	if (is_in_groups(group_name)) {
		return 0;
	}

	if (cJSON_GetArraySize(all_groups) >= sizeof(group_t) * 8) {
		log_err("Only %zu distinct groups are supported!", sizeof(group_t) * 8);
		return -1;
	}
	cJSON_AddItemToArray(all_groups, cJSON_CreateString(group_name));
	return 0;
}

int create_groups(void) {
	all_groups = cJSON_CreateArray();
	if (all_groups == NULL) {
		return -1;
	}

	return 0;
}

void free_groups(void)
{
	if (all_groups != NULL) {
		cJSON_free(all_groups);
	}
}

int add_groups(const cJSON *group_array)
{
	if ((group_array == NULL) || (group_array->type != cJSON_Array)) {
		return 0;
	}

	unsigned int array_size = cJSON_GetArraySize(group_array);
	for (unsigned int i = 0; i < array_size; ++i) {
		const cJSON *group = cJSON_GetArrayItem(group_array, i);
		if (group->type == cJSON_String) {
			if (add_group(group->valuestring) < 0) {
				return -1;
			}
		}
	}

	return 0;
}

group_t get_groups(const cJSON *peer_groups)
{
	if ((peer_groups == NULL) || (peer_groups->type != cJSON_Array)) {
		return 0;
	}

	group_t groups = 0;
	unsigned int array_size = cJSON_GetArraySize(peer_groups);
	for (unsigned int i = 0; i < array_size; ++i) {
		const cJSON *peer_group = cJSON_GetArrayItem(peer_groups, i);
		if (peer_group->type == cJSON_String) {

			unsigned int all_groups_array_size = cJSON_GetArraySize(all_groups);
			for (unsigned int j = 0; j < all_groups_array_size; ++j) {
				const cJSON *group = cJSON_GetArrayItem(all_groups, j);
				if (strcmp(group->valuestring, peer_group->valuestring) == 0) {
					groups |= (1 << j);
				}
			}
		}
	}

	return groups;
}
