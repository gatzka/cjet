#ifndef CJET_IO_H
#define CJET_IO_H

#include "list.h"

int run_io(volatile int *shall_close);
int run_io_mt(volatile int *shall_close);

struct io {
	int fd;
	struct list_head list;
};

#endif
