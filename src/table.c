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

#include "compiler.h"
#include "generated/cjet_config.h"
#include "hashtable.h"
#include "table.h"


DECLARE_HASHTABLE_STRING(element_table, CONFIG_ELEMENT_TABLE_ORDER, 1U)

static struct hashtable_string *element_hashtable = NULL;

int element_hashtable_create(void)
{
	element_hashtable = HASHTABLE_CREATE(element_table);
	if (unlikely(element_hashtable == NULL)) {
		return -1;
	}
	return 0;
}

void element_hashtable_delete(void)
{
	HASHTABLE_DELETE(element_table, element_hashtable);
}

int element_table_put(const char *path, void *value)
{
	struct value_element_table new_val;
	new_val.vals[0] = value;
	return HASHTABLE_PUT(element_table, element_hashtable, path, new_val, NULL);
}

void *element_table_get(const char *path)
{
	struct value_element_table val;
	int ret = HASHTABLE_GET(element_table, element_hashtable, path, &val);
	if (ret == HASHTABLE_SUCCESS) {
		return val.vals[0];
	} else {
		return NULL;
	}
}

void element_table_remove(const char *path)
{
	int ret = HASHTABLE_REMOVE(element_table, element_hashtable, path, NULL);
	if (ret == 0) {}
}
