static inline unsigned int hash_func_string(const char* key)
{
	unsigned int hash = 0;
	int c;
	while ((c = *key++) != 0)
		hash = c + (hash << 6) + (hash << 16) - hash;
	return hash;
}

