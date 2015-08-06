#ifndef CJET_MESSAGE_H
#define CJET_MESSAGE_H

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
