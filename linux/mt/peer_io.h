#ifndef CJET_PEER_IO_H
#define CJET_PEER_IO_H

#include <pthread.h>

#include "list.h"

struct io {
	int fd;
	struct list_head list;
	pthread_t thread_id;
};

#endif
