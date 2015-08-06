#ifndef CJET_IO_H
#define CJET_IO_H

#include "peer.h"

#ifdef __cplusplus
extern "C" {
#endif

int send_message(struct peer *p, const char *rendered, size_t len);
int add_io(struct peer *p);
void remove_io(const struct peer *p);

#ifdef __cplusplus
}
#endif

#endif
