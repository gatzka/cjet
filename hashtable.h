/*
 * General description. This file implements a hash table based on an
 * algorithm called hopscotch hashing. Hopscotch hashing is an closed
 * hashing algorithm with open addressing. The main idea is to encode
 * the distance to the calculated hash position in a bitmap associated
 * with each hash index. When inserting a key/value pair the algorithm
 * tries to reorder hash table entries that each entry is in the maximum
 * distance the bitmap can contain. (HOP_RANGE in this implementation).
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
 * The typical usage for example is:
 * DECLARE_HASHTABLE_UINT32(CANHARDWARE_HASHTABLE, 13)
 * hashtable = HASHTABLE_CREATE(CANHARDWARE_HASHTABLE);
 * HASHTABLE_PUT(CANHARDWARE_HASHTABLE, hashtable, key, value, prev_value);
 * value = HASHTABLE_GET(CANHARDWARE_HASHTABLE, hashtable, key);
 */

#ifndef HASHTABLE_H
#define HASHTABLE_H

#include <stdint.h>

typedef uint32_t u32;
typedef uint64_t u64;

#define wmb()

#define HASHTABLE_SUCCESS 0
#define HASHTABLE_FULL -1
#define HASHTABLE_KEYINVAL -2
#define HASHTABLE_INVALIDENTRY	-1

static const u32 hash32_magic = 2654435769U;
static const u64 hash64_magic = 0xd43ece626aa9260aull;

static inline int is_equal_string(const char *s1, const char *s2)
{
	return !strcmp(s1, s2);
}

static inline int is_equal_u32(u32 a, u32 b)
{
	return a == b;
}

static inline int is_equal_u64(u64 a, u64 b)
{
	return a == b;
}

/*
 * The bit position in hop_info shows the relative distance beginning
 * from the hash position where to find collision entries. So the
 * HOP_RANGE is the size of the hop_info field in bytes multiplied be
 * the number of bits per byte (8).
 */
#define HOP_RANGE (sizeof(((struct hashtable_u32*)0)->hop_info) * 8)

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
#define DECLARE_HASHTABLE(name, order, type_name, type) \
\
struct hashtable_u32 { \
	u32 hop_info; \
	u32 key; \
	void *value; \
}; \
\
struct hashtable_u64 { \
	u32 hop_info; \
	u64 key; \
	void *value; \
}; \
\
struct hashtable_string { \
	u32 hop_info; \
	const char *key; \
	void *value; \
}; \
\
static const u32 add_range_##name = (1 << (order - 1)); \
static const u32 table_size_##name = (1 << (order)); \
\
static inline u32 wrap_pos##name(u32 pos) \
{ \
	return pos & (table_size_##name - 1); \
} \
\
static inline u32 hash_func_##name##_u32(u32 key) \
{ \
	return (key * (hash32_magic) >> (32 - (order))); \
} \
\
static inline u32 hash_func_##name##_string(const char* key) \
{ \
	u32 hash = 0; \
	u32 c; \
	while ((c = (u32)*key++) != 0) \
		hash = c + (hash << 6u) + (hash << 16u) - hash; \
	hash = (hash * (hash32_magic)) >> (32u - (order)); \
	return hash; \
} \
\
static inline struct hashtable_##type_name *hashtable_create_##name(void) \
{ \
	size_t i; \
	struct hashtable_##type_name *table = (struct hashtable_##type_name *)malloc(table_size_##name * sizeof(struct hashtable_##type_name)); \
	if (table != NULL) { \
		for (i = 0; i < table_size_##name; i++) { \
			table[i].key = (type)HASHTABLE_INVALIDENTRY; \
			table[i].hop_info = 0; \
			table[i].value = NULL; \
		} \
	} \
	return table; \
} \
\
static inline void hashtable_delete_##name(struct hashtable_##type_name *table) \
{ \
	free(table); \
	return; \
} \
\
static inline void *hashtable_get_##name(struct hashtable_##type_name *table, type key) \
{ \
	u32 hash_pos = hash_func_##name##_##type_name(key); \
	u32 pos = hash_pos; \
	u32 hop_info = table[hash_pos].hop_info; \
	while (hop_info != 0) { \
		if ((hop_info & 0x1) == 1) { \
			if (is_equal_##type_name(table[pos].key, key)) { \
				return table[pos].value; \
			} \
		} \
		hop_info = hop_info >> 1; \
		pos = wrap_pos##name(pos + 1); \
	} \
	return NULL; \
} \
\
static inline u32 find_closer_entry_##name(struct hashtable_##type_name *table, u32 free_position) \
{ \
	u32 check_distance = (HOP_RANGE - 1); \
	while (check_distance > 0) { \
		u32 check_position = wrap_pos##name(free_position - check_distance); \
		u32 check_hop_info = table[check_position].hop_info; \
		u32 i; \
		u32 mask = 1; \
		u32 hop_position = 0xffffffff; \
		for (i = 0; i < check_distance; i++, mask <<= 1) { \
			if ((mask & check_hop_info) != 0) { \
				hop_position = wrap_pos##name(check_position + i); \
				break; \
			} \
		} \
		if (hop_position != 0xffffffff) { \
/* We found a table entry to swap the free entry with. */ \
			table[free_position].key = table[hop_position].key; \
			table[free_position].value = table[hop_position].value; \
			wmb(); \
			check_hop_info = check_hop_info & ~(mask); \
			check_hop_info = check_hop_info | (1 << check_distance); \
			table[check_position].hop_info = check_hop_info; \
			return hop_position ;\
		} \
		check_distance--; \
	} \
	return 0xffffffff; \
} \
\
static inline int hashtable_put_##name(struct hashtable_##type_name *table, type key, void *value, void **prev_value) \
{ \
	u32 hash_pos; \
	u32 pos; \
	u32 hop_info; \
	u32 free_distance; \
	u32 free_pos; \
	if (prev_value != NULL) { \
		*prev_value = NULL; \
	} \
	if (key == (type)HASHTABLE_INVALIDENTRY) { \
		return HASHTABLE_KEYINVAL; \
	} \
\
/* Look if the key is already in the table. */ \
	hash_pos = hash_func_##name##_##type_name(key); \
	pos = hash_pos; \
	hop_info = table[hash_pos].hop_info; \
	while (hop_info != 0) { \
		if ((hop_info & 0x1) == 1) { \
			if (is_equal_##type_name(table[pos].key, key)) { \
				if (prev_value != NULL) { \
					*prev_value = table[pos].value; \
				} \
				table[pos].value = value; \
				return HASHTABLE_SUCCESS; \
			} \
		} \
		hop_info = hop_info >> 1; \
		pos = wrap_pos##name(pos + 1); \
	} \
\
/* The key wasn't found, so let's insert. */ \
/* Make linear search from hash_pos to add_range_##name to find an empty table entry. */ \
	free_distance = 0; \
	pos = hash_pos; \
	while (free_distance < add_range_##name) { \
		if (table[pos].key == (type)HASHTABLE_INVALIDENTRY) { \
			break; \
		} \
		free_distance++; \
		pos = wrap_pos##name(pos + 1); \
	} \
	free_pos = pos; \
	if (free_distance < add_range_##name) { \
		do { \
			if (free_distance < HOP_RANGE) { \
				table[free_pos].value = value; \
				table[free_pos].key = key; \
				wmb(); \
				hop_info = table[hash_pos].hop_info; \
				hop_info = hop_info | (1 << free_distance); \
				table[hash_pos].hop_info = hop_info; \
				return HASHTABLE_SUCCESS; \
			} else { \
/* Now we must try to swap some entries */ \
				free_pos = find_closer_entry_##name(table, free_pos); \
				free_distance = wrap_pos##name(free_pos - hash_pos); \
			} \
		} while (free_pos != 0xffffffff); \
	} \
	return HASHTABLE_FULL; \
} \
\
static inline void *hashtable_remove_##name(struct hashtable_##type_name *table, type key) \
{ \
	void *ret = NULL; \
	u32 hash_pos = hash_func_##name##_##type_name(key); \
	u32 pos = hash_pos; \
	u32 hop_info = table[hash_pos].hop_info; \
	u32 check_hop_info = hop_info; \
	while (check_hop_info != 0) { \
		if ((check_hop_info & 0x1) == 1) { \
			if (is_equal_##type_name(table[pos].key, key)) { \
				u32 distance; \
				ret = table[pos].value; \
				table[pos].key = (type)HASHTABLE_INVALIDENTRY; \
				wmb(); \
				table[pos].value = NULL; \
				distance = wrap_pos##name(pos - hash_pos); \
				table[hash_pos].hop_info = hop_info & ~(1 << distance); \
				break; \
			} \
		} \
		check_hop_info = check_hop_info >> 1; \
		pos = wrap_pos##name(pos + 1); \
	} \
	return ret; \
}

#define DECLARE_HASHTABLE_STRING(name, order) DECLARE_HASHTABLE(name, order, string, const char *)
#define DECLARE_HASHTABLE_UINT32(name, order) DECLARE_HASHTABLE(name, order, u32, u32)
#define DECLARE_HASHTABLE_UINT64(name, order) DECLARE_HASHTABLE(name, order, u64, u64)

/*
 * Creates a hash table.
 */
#define HASHTABLE_CREATE(name) \
	hashtable_create_##name()

/*
 * Destroys a hash table.
 */
#define HASHTABLE_DELETE(name, table) \
	hashtable_delete_##name((table)); \
	table = NULL;

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
#define HASHTABLE_GET(name, table, key) \
	hashtable_get_##name((table), (key))

/*
 * Removes a key/value pair from table. If a value was found for
 * key, it will be returned, NULL otherwise.
 */
#define HASHTABLE_REMOVE(name, table, key) \
	hashtable_remove_##name((table), (key))

#endif
