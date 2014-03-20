#ifndef CJET_PEER_IO_OPS_H
#define CJET_PEER_IO_OPS_H

#include "peer.h"

#ifdef __cplusplus
extern "C" {
#endif

int send_message(struct peer *p, char *rendered, size_t len);

#ifdef __cplusplus
}
#endif

#endif
