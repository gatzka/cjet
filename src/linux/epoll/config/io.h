#ifndef CJET_IO_H
#define CJET_IO_H

#include "peer.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IO_CLOSE -1
#define IO_WOULD_BLOCK -2
#define IO_ERROR -3

int run_io(void);
char *get_read_ptr(struct peer *p, unsigned int count);
int copy_msg_to_write_buffer(struct peer *p, const void *rendered, uint32_t msg_len_be, size_t already_written);
int handle_all_peer_operations(struct peer *p);
int send_buffer(struct peer *p);

#ifdef __cplusplus
}
#endif

#endif
