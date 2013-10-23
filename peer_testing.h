#ifndef CJET_PEER_TESTING_H
#define CJET_PEER_TESTING_H

#ifdef TESTING

#ifdef __cplusplus
extern "C" {
#endif

int fake_read(int fd, void *buf, size_t count);

#ifdef __cplusplus
}
#endif

#define READ fake_read
#define SEND fake_send_

#else

#define READ read
#define SEND send

#endif

#endif
