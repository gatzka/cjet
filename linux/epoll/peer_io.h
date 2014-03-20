#ifndef CJET_PEER_IO_H
#define CJET_PEER_IO_H

#include "list.h"

struct io {
	int fd;
	struct list_head list;
};

#endif
