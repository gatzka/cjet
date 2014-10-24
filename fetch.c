#include <stdlib.h>

#include "compiler.h"
#include "fetch.h"
#include "peer.h"

#if 0
struct fetch *alloc_fetch(void)
{
	struct fetch *f = calloc(1, sizeof(*f));
	if (unlikely(f == NULL)) {
		return NULL;
	}
	INIT_LIST_HEAD(&f->next_fetch);
	INIT_LIST_HEAD(&f->matcher_list);

	return f;
}
#endif

cJSON *add_fetch_to_peer(struct peer *p, cJSON *params)
{
	return NULL;
}
