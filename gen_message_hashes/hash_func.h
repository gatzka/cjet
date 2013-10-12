static inline uint32_t hash_func_string(const char* key)
{
	uint32_t hash = 0;
	int c;
	while ((c = *key++) != 0)
		hash = c + (hash << 6) + (hash << 16) - hash;
	return hash;
}

