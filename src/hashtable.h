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

/*
 * General description. This file implements a hash table based on an
 * algorithm called hopscotch hashing. Hopscotch hashing is an closed
 * hashing algorithm with open addressing. The main idea is to encode
 * the distance to the calculated hash position in a bitmap associated
 * with each hash index. When inserting a key/value pair the algorithm
 * tries to reorder hash table entries that each entry is in the maximum
 * distance the bitmap can contain. (hop_range in this implementation).
 *
 * This implementation is lock free but only ensure the following
 * condition. Every HASHTABLE_REMOVE or HASHTABLE_PUT call can be
 * interrupted at any time by a call to HASHTABLE_GET. Because
 * HASHTABLE_GET does not alter the hash table, concurrent calls to
 * HASHTABLE_GET are also allowed.
 *
 * Please be aware that concurrent calls to HASHTABLE_REMOVE or
 * HASHTABLE_PUT are not allowed and must be synchronized elsewhere.
 *
 * Please use only the macros DECLARE_HASHTABLE_STRING,
 * DECLARE_HASHTABLE_UINT32, DECLARE_HASHTABLE_UINT64,
 * HASHTABLE_CREATE, HASHTABLE_DELETE, HASHTABLE_GET,
 * HASHTABLE_REMOVE and HASHTABLE_PUT.
 * Do not call the other functions directly.
 *
 * Please note that HASHTABLE_CREATE shall only called from Linux
 * context, never from IRQ context because it allocates memory with
 * GFP_KERNEL.
 *
 * The typical usage for example is:
 * DECLARE_HASHTABLE_UINT32(CANHARDWARE_HASHTABLE, 13)
 * hashtable = HASHTABLE_CREATE(CANHARDWARE_HASHTABLE);
 * HASHTABLE_PUT(CANHARDWARE_HASHTABLE, hashtable, key, value, prev_value);
 * value = HASHTABLE_GET(CANHARDWARE_HASHTABLE, hashtable, key);
 */

#ifndef HASHTABLE_H
#define HASHTABLE_H

#include <stdint.h>
#include <string.h>

#include "alloc.h"
#include "compiler.h"

#define GFP_KERNEL 1

#define kmalloc(size, priority) cjet_malloc(size)
#define kfree(__ptr) cjet_free(__ptr)

#define HASHTABLE_SUCCESS 0
#define HASHTABLE_FULL -1
#define HASHTABLE_KEYINVAL -2
#define HASHTABLE_INVALIDENTRY -1

static inline uint32_t hs_hash32(uint32_t key, unsigned int order)
{
	key = (key ^ 61) ^ (key >> 16);
	key = key + (key << 3);
	key = key ^ (key >> 4);
	key = key * 0x27d4eb2d;
	key = key ^ (key >> 15);
	return (key >> (32 - (order)));
}

static inline uint32_t hs_hash6432shift(uint64_t key, unsigned int order)
{
	key = (~key) + (key << 18);
	key = key ^ (key >> 31);
	key = key * 21;
	key = key ^ (key >> 11);
	key = key + (key << 6);
	key = key ^ (key >> 22);
	return ((uint32_t)key) >> (32 - (order));
}

/*
 * Declares a hash table of name "name" and size 2^order. This macro is
 * just for internal use. Do not use it to declare a hash table, use
 * DECLARE_HASHTABLE_STRING, DECLARE_HASHTABLE_UINT32 or
 * DECLARE_HASHTABLE_UINT64 instead.
 *
 * There are two different macro parameters required for the type of the
 * hash table: type_name and type. type_name denotes the unique name
 * that must be appended to all typed functions, type denotes the
 * underlying C type that is used in the hash table. This is only
 * required for the case of a string hash table. Here we have "type_name
 * string" and type "const char *". Please see also
 * DECLARE_HASHTABLE_STRING.
 */
#define DECLARE_HASHTABLE(name, order, type_name, type, value_entries)                                                                                                            \
                                                                                                                                                                                  \
	static const uint32_t add_range_##name = (1 << (order - 1));                                                                                                              \
	static const uint32_t table_size_##name = (1 << (order));                                                                                                                 \
                                                                                                                                                                                  \
	static inline uint32_t wrap_pos##name(uint32_t pos)                                                                                                                       \
	{                                                                                                                                                                         \
		return pos & (table_size_##name - 1);                                                                                                                             \
	}                                                                                                                                                                         \
                                                                                                                                                                                  \
	static inline struct hashtable_##type_name *hashtable_create_##name(void)                                                                                                 \
	{                                                                                                                                                                         \
		struct hashtable_##type_name *table = (struct hashtable_##type_name *)kmalloc(table_size_##name * sizeof(struct hashtable_##type_name), GFP_KERNEL);              \
		if (table != NULL) {                                                                                                                                              \
			size_t i;                                                                                                                                                 \
			for (i = 0; i < table_size_##name; ++i) {                                                                                                                 \
				memset(&table[i], 0, sizeof(table[0]));                                                                                                           \
				table[i].key = (type)HASHTABLE_INVALIDENTRY;                                                                                                      \
			}                                                                                                                                                         \
		}                                                                                                                                                                 \
		return table;                                                                                                                                                     \
	}                                                                                                                                                                         \
                                                                                                                                                                                  \
	static inline void hashtable_delete_##name(struct hashtable_##type_name *table)                                                                                           \
	{                                                                                                                                                                         \
		kfree(table);                                                                                                                                                     \
		return;                                                                                                                                                           \
	}                                                                                                                                                                         \
                                                                                                                                                                                  \
	_Pragma("GCC diagnostic ignored \"-Wunused-function\"") static inline int hashtable_get_##name(struct hashtable_##type_name *table, type key, struct value_##name *value) \
	{                                                                                                                                                                         \
		uint32_t hash_pos = hash_func_##name##_##type_name(key);                                                                                                          \
		uint32_t pos = hash_pos;                                                                                                                                          \
		uint32_t hop_info = table[hash_pos].hop_info;                                                                                                                     \
		while (hop_info != 0) {                                                                                                                                           \
			if (((hop_info & 0x1) == 1) && (is_equal_##type_name(table[pos].key, key))) {                                                                             \
				*value = table[pos].value;                                                                                                                        \
				return HASHTABLE_SUCCESS;                                                                                                                         \
			}                                                                                                                                                         \
			hop_info = hop_info >> 1;                                                                                                                                 \
			pos = wrap_pos##name(pos + 1);                                                                                                                            \
		}                                                                                                                                                                 \
		return HASHTABLE_INVALIDENTRY;                                                                                                                                    \
	}                                                                                                                                                                         \
	_Pragma("GCC diagnostic error \"-Wunused-function\"")                                                                                                                     \
                                                                                                                                                                                  \
	    static inline uint32_t hop_range_##name(void)                                                                                                                         \
	{                                                                                                                                                                         \
		return sizeof(((struct hashtable_##type_name *)0)->hop_info) * 8;                                                                                                 \
	}                                                                                                                                                                         \
                                                                                                                                                                                  \
	static inline uint32_t find_closer_entry_##name(struct hashtable_##type_name *table, uint32_t free_position)                                                              \
	{                                                                                                                                                                         \
		uint32_t check_distance = (hop_range_##name() - 1);                                                                                                               \
		while (check_distance > 0) {                                                                                                                                      \
			unsigned int i;                                                                                                                                           \
			uint32_t check_position = wrap_pos##name(free_position - check_distance);                                                                                 \
			uint32_t check_hop_info = table[check_position].hop_info;                                                                                                 \
			uint32_t mask = 1;                                                                                                                                        \
			uint32_t hop_position = 0xffffffff;                                                                                                                       \
			for (i = 0; i < check_distance; ++i) {                                                                                                                    \
				if ((mask & check_hop_info) != 0) {                                                                                                               \
					hop_position = wrap_pos##name(check_position + i);                                                                                        \
					break;                                                                                                                                    \
				}                                                                                                                                                 \
				mask = mask << 1;                                                                                                                                 \
			}                                                                                                                                                         \
			if (hop_position != 0xffffffff) {                                                                                                                         \
				/* We found a table entry to swap the free entry with. */                                                                                         \
				table[free_position].key = table[hop_position].key;                                                                                               \
				table[free_position].value = table[hop_position].value;                                                                                           \
				wmb();                                                                                                                                            \
				check_hop_info = check_hop_info & ~(mask);                                                                                                        \
				check_hop_info = check_hop_info | (UINT32_C(1) << check_distance);                                                                                          \
				table[check_position].hop_info = check_hop_info;                                                                                                  \
				return hop_position;                                                                                                                              \
			}                                                                                                                                                         \
			--check_distance;                                                                                                                                         \
		}                                                                                                                                                                 \
		return 0xffffffff;                                                                                                                                                \
	}                                                                                                                                                                         \
                                                                                                                                                                                  \
	static inline int hashtable_put_##name(struct hashtable_##type_name *table, type key, struct value_##name value, struct value_##name *prev_value)                         \
	{                                                                                                                                                                         \
		uint32_t hash_pos;                                                                                                                                                \
		uint32_t pos;                                                                                                                                                     \
		uint32_t hop_info;                                                                                                                                                \
		uint32_t free_distance;                                                                                                                                           \
		uint32_t free_pos;                                                                                                                                                \
		if (prev_value != NULL) {                                                                                                                                         \
			memset(prev_value, 0, sizeof(*prev_value));                                                                                                               \
		}                                                                                                                                                                 \
		if (key == (type)HASHTABLE_INVALIDENTRY) {                                                                                                                        \
			return HASHTABLE_KEYINVAL;                                                                                                                                \
		}                                                                                                                                                                 \
                                                                                                                                                                                  \
		/* Look if the key is already in the table. */                                                                                                                    \
		hash_pos = hash_func_##name##_##type_name(key);                                                                                                                   \
		pos = hash_pos;                                                                                                                                                   \
		hop_info = table[hash_pos].hop_info;                                                                                                                              \
		while (hop_info != 0) {                                                                                                                                           \
			if (((hop_info & 0x1) == 1) && (is_equal_##type_name(table[pos].key, key))) {                                                                             \
				if (prev_value != NULL) {                                                                                                                         \
					*prev_value = table[pos].value;                                                                                                           \
				}                                                                                                                                                 \
				table[pos].value = value;                                                                                                                         \
				return HASHTABLE_SUCCESS;                                                                                                                         \
			}                                                                                                                                                         \
			hop_info = hop_info >> 1;                                                                                                                                 \
			pos = wrap_pos##name(pos + 1);                                                                                                                            \
		}                                                                                                                                                                 \
                                                                                                                                                                                  \
		/* The key wasn't found, so let's insert. */                                                                                                                      \
		/* Make linear search from hash_pos to add_range_##name to find an empty table entry. */                                                                          \
		free_distance = 0;                                                                                                                                                \
		pos = hash_pos;                                                                                                                                                   \
		while (free_distance < add_range_##name) {                                                                                                                        \
			if (table[pos].key == (type)HASHTABLE_INVALIDENTRY) {                                                                                                     \
				break;                                                                                                                                            \
			}                                                                                                                                                         \
			++free_distance;                                                                                                                                          \
			pos = wrap_pos##name(pos + 1);                                                                                                                            \
		}                                                                                                                                                                 \
		free_pos = pos;                                                                                                                                                   \
		if (free_distance < add_range_##name) {                                                                                                                           \
			do {                                                                                                                                                      \
				if (free_distance < hop_range_##name()) {                                                                                                         \
					table[free_pos].value = value;                                                                                                            \
					table[free_pos].key = key;                                                                                                                \
					wmb();                                                                                                                                    \
					hop_info = table[hash_pos].hop_info;                                                                                                      \
					hop_info = hop_info | (UINT32_C(1) << free_distance);                                                                                               \
					table[hash_pos].hop_info = hop_info;                                                                                                      \
					return HASHTABLE_SUCCESS;                                                                                                                 \
				} else {                                                                                                                                          \
					/* Now we must try to swap some entries */                                                                                                \
					free_pos = find_closer_entry_##name(table, free_pos);                                                                                     \
					free_distance = wrap_pos##name(free_pos - hash_pos);                                                                                      \
				}                                                                                                                                                 \
			} while (free_pos != 0xffffffff);                                                                                                                         \
		}                                                                                                                                                                 \
		return HASHTABLE_FULL;                                                                                                                                            \
	}                                                                                                                                                                         \
                                                                                                                                                                                  \
	static inline int hashtable_remove_##name(struct hashtable_##type_name *table, type key, struct value_##name *value)                                                      \
	{                                                                                                                                                                         \
		uint32_t hash_pos = hash_func_##name##_##type_name(key);                                                                                                          \
		uint32_t pos = hash_pos;                                                                                                                                          \
		uint32_t hop_info = table[hash_pos].hop_info;                                                                                                                     \
		uint32_t check_hop_info = hop_info;                                                                                                                               \
		while (check_hop_info != 0) {                                                                                                                                     \
			if (((check_hop_info & 0x1) == 1) && (is_equal_##type_name(table[pos].key, key))) {                                                                       \
				uint32_t distance;                                                                                                                                \
				if (value != NULL) {                                                                                                                              \
					*value = table[pos].value;                                                                                                                \
				}                                                                                                                                                 \
				table[pos].key = (type)HASHTABLE_INVALIDENTRY;                                                                                                    \
				wmb();                                                                                                                                            \
				memset(&table[pos].value, 0, sizeof(table[pos].value));                                                                                           \
				distance = wrap_pos##name(pos - hash_pos);                                                                                                        \
				table[hash_pos].hop_info = hop_info & ~(UINT32_C(1) << distance);                                                                                           \
				return HASHTABLE_SUCCESS;                                                                                                                         \
			}                                                                                                                                                         \
			check_hop_info = check_hop_info >> 1;                                                                                                                     \
			pos = wrap_pos##name(pos + 1);                                                                                                                            \
		}                                                                                                                                                                 \
		return HASHTABLE_INVALIDENTRY;                                                                                                                                    \
	}

#define DECLARE_HASHTABLE_STRING(name, order, value_entries)                \
	struct value_##name {                                               \
		void *vals[value_entries];                                  \
	};                                                                  \
	struct hashtable_string {                                           \
		uint32_t hop_info;                                          \
		const char *key;                                            \
		struct value_##name value;                                  \
	};                                                                  \
	static inline uint32_t hash_func_##name##_string(const char *key)   \
	{                                                                   \
		uint32_t hash = 0;                                          \
		uint32_t c = *key;                                          \
		++key;                                                      \
		while (c != 0) {                                            \
			hash = ((c + (hash << 6U)) + (hash << 16U)) - hash; \
			c = *key;                                           \
			++key;                                              \
		}                                                           \
		return hs_hash32(hash, order);                              \
	}                                                                   \
	static inline int is_equal_string(const char *s1, const char *s2)   \
	{                                                                   \
		return !strcmp(s1, s2);                                     \
	}                                                                   \
	DECLARE_HASHTABLE(name, order, string, const char *, value_entries)

#define DECLARE_HASHTABLE_UINT32(name, order, value_entries)             \
	struct value_##name {                                            \
		void *vals[value_entries];                               \
	};                                                               \
	struct hashtable_uint32_t {                                      \
		uint32_t hop_info;                                       \
		uint32_t key;                                            \
		struct value_##name value;                               \
	};                                                               \
	static inline uint32_t hash_func_##name##_uint32_t(uint32_t key) \
	{                                                                \
		return hs_hash32(key, order);                            \
	}                                                                \
                                                                         \
	static inline int is_equal_uint32_t(uint32_t a, uint32_t b)      \
	{                                                                \
		return a == b;                                           \
	}                                                                \
                                                                         \
	DECLARE_HASHTABLE(name, order, uint32_t, uint32_t, value_entries)

#define DECLARE_HASHTABLE_UINT64(name, order, value_entries)             \
	struct value_##name {                                            \
		void *vals[value_entries];                               \
	};                                                               \
	struct hashtable_uint64_t {                                      \
		uint32_t hop_info;                                       \
		uint64_t key;                                            \
		struct value_##name value;                               \
	};                                                               \
	static inline uint32_t hash_func_##name##_uint64_t(uint64_t key) \
	{                                                                \
		return hs_hash6432shift(key, order);                        \
	}                                                                \
                                                                         \
	static inline int is_equal_uint64_t(uint64_t a, uint64_t b)      \
	{                                                                \
		return a == b;                                           \
	}                                                                \
                                                                         \
	DECLARE_HASHTABLE(name, order, uint64_t, uint64_t, value_entries)

/*
 * Creates a hash table.
 */
#define HASHTABLE_CREATE(name) \
	hashtable_create_##name()

/*
 * Destroys a hash table.
 */
#define HASHTABLE_DELETE(name, table)     \
	hashtable_delete_##name((table)); \
	table = NULL

/*
 * Maps the key to the value in table. Return values:
 * HASHTABLE_FULL: no space left in hash_table
 * HASHTABLE_KEYINVAL: invalid key (HASHTABLE_INVALIDENTRY)
 * HASHTABLE_SUCCESS: everything o.k.
 *
 * if prev_value != NULL, the previous value stored for this
 * key will be assigned to prev_value
 */
#define HASHTABLE_PUT(name, table, key, value, prev_value) \
	hashtable_put_##name((table), (key), (value), (prev_value))

/*
 * Returns the value stored for key or NULL if no value was found for
 * key.
 */
#define HASHTABLE_GET(name, table, key, value) \
	hashtable_get_##name((table), (key), (value))

/*
 * Removes a key/value pair from table. If a value was found for
 * key, it will be returned, NULL otherwise.
 */
#define HASHTABLE_REMOVE(name, table, key, value) \
	hashtable_remove_##name((table), (key), (value))

#endif
