#ifndef CJET_PEER_TESTING_H
#define CJET_PEER_TESTING_H

#ifdef TESTING

#include <sys/uio.h>

#ifdef __cplusplus
extern "C" {
#endif

int fake_read(int fd, void *buf, size_t count);
int fake_send(int fd, void *buf, size_t count, int flags);
int fake_writev(int fd, const struct iovec *iov, int iovcnt);

#ifdef __cplusplus
}
#endif

#define READ fake_read
#define SEND fake_send
#define WRITEV fake_writev
#else

#define READ read
#define SEND send
#define WRITEV writev

#endif

#endif
