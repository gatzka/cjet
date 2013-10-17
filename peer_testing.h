#ifndef CJET_PEER_TESTING_H
#define CJET_PEER_TESTING_H

#ifdef TESTING

#ifdef __cplusplus
extern "C" {
#endif
ssize_t fake_read(int fd, void *buf, size_t count);

#ifdef __cplusplus
}
#endif

#define READ \
	fake_read

#else

#define READ \
	read
#endif

#endif
