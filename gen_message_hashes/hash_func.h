static inline uint32_t hash_func_string(const char* key)
{
	uint32_t hash = 0;
	uint32_t c;
	while ((c = (uint32_t)*key++) != 0)
		hash = c + (hash << 6u) + (hash << 16u) - hash;
	return hash;
}

