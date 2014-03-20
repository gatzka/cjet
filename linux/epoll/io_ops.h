#ifndef CJET_IO_OPS_H
#define CJET_IO_OPS_H

#include "peer.h"

int send_message(struct peer *p, char *rendered, size_t len);

#endif
