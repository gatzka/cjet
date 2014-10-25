#ifndef CJET_PEER_IO_H
#define CJET_PEER_IO_H

#include <pthread.h>

#include "list.h"

struct io {
	int fd;
	pthread_t thread_id;
	int is_dead;
	pthread_mutex_t death_mutex;
	pthread_cond_t death_cv;
};

#endif
