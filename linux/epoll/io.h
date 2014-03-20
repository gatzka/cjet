#ifndef CJET_IO_H
#define CJET_IO_H

#include "peer.h"

#ifdef __cplusplus
extern "C" {
#endif

int run_io(volatile int *shall_close);
char *get_read_ptr(struct peer *p, unsigned int count);
int handle_all_peer_operations(struct peer *p);
int send_buffer(struct peer *p);

#ifdef __cplusplus
}
#endif

#endif
