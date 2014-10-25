#ifndef CJET_IO_H
#define CJET_IO_H

#include "peer.h"

int run_io(void);
int send_message(struct peer *p, const char *rendered, size_t len);

#endif
