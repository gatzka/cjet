#ifndef CJET_IO_H
#define CJET_IO_H

#include "config.h"

int run_io_epoll(volatile int *shall_close);
int run_io_mt(volatile int *shall_close);

#if defined LINUX_IO_EPOLL
struct io {
	int fd;
};

#define RUN_IO run_io_epoll

#elif defined LINUX_IO_MT 

struct io {
	int fd;
};

#define RUN_IO run_io_mt

#endif

#endif
