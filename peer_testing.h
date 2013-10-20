#ifndef CJET_PEER_TESTING_H
#define CJET_PEER_TESTING_H

#ifdef TESTING

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <sys/uio.h>

ssize_t fake_read(int fd, void *buf, size_t count);
ssize_t fake_write(int fd, const void *buf, size_t count);
ssize_t fake_writev(int fd, const struct iovec *iov, int iovcnt);

#ifdef __cplusplus
}
#endif

#define READ fake_read
#define WRITE fake_write
#define WRITEV fake_writev

#else

#define READ read
#define WRITE write
#define WRITEV writev
#endif

#endif
