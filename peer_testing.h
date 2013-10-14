#ifndef CJET_PEER_TESTING_H
#define CJET_PEER_TESTING_H

#ifdef TESTING
#define READ \
	fake_read
#else
#define READ \
	read
#endif

#endif
