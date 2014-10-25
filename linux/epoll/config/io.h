#ifndef CJET_IO_H
#define CJET_IO_H

#include "peer.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IO_WOULD_BLOCK -2

int run_io(void);
char *get_read_ptr(struct peer *p, unsigned int count);
int handle_all_peer_operations(struct peer *p);
int send_buffer(struct peer *p);
int send_message(struct peer *p, const char *rendered, size_t len);

#ifdef __cplusplus
}
#endif

#endif
