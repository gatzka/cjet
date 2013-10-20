#include <stdlib.h>

#include "cJSON.h"
#include "compiler.h"
#include "peer.h"
#include "state.h"

static struct state *alloc_state() {
	struct state *s;
	s = malloc(sizeof(*s));
	if (unlikely(s == NULL)) {
		return NULL;
	}
	INIT_LIST_HEAD(&s->next_state);

	return s;
}

int add_state_to_peer(struct peer *p, const char *path, cJSON *value)
{
	/*
	 * TODO: Check if the state exists in ALL peers available!
	 */

	return 0;
}
