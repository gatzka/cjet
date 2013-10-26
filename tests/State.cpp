#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MAIN
#define BOOST_TEST_MODULE state

#include <boost/test/unit_test.hpp>

#include "../peer.h"
#include "../state.h"

extern "C" {

	int parse_message(const char *msg, uint32_t length, struct peer *p)
	{
		return 0;
	}

	int fake_read(int fd, void *buf, size_t count)
	{
		return 0;
	}

	int fake_send(int fd, void *buf, size_t count, int flags)
	{
		return count;
	}
}

BOOST_AUTO_TEST_CASE(test1)
{
	struct peer *p = alloc_peer(-1);
	free_peer(p);
}

