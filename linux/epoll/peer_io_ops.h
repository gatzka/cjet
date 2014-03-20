#ifndef CJET_PEER_IO_OPS_H
#define CJET_PEER_IO_OPS_H

#include "peer.h"

int send_message(struct peer *p, char *rendered, size_t len);

#endif
