#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MAIN
#define BOOST_TEST_MODULE state

#include <boost/test/unit_test.hpp>

#include "peer.h"

extern "C" {
	int add_io(struct peer *p)
	{
		return 0;
	}

	void remove_io(const struct peer *p)
	{
		return;
	}

	void remove_all_methods_from_peer(struct peer *p)
	{
	}

	void remove_all_fetchers_from_peer(struct peer *p)
	{
	}

	void remove_peer_from_routing_table(const struct peer *p,
		const struct peer *peer_to_remove)
	{
	}

	void remove_routing_info_from_peer(const struct peer *p)
	{
	}

	void remove_all_states_from_peer(struct peer *p)
	{
	}

	void delete_routing_table(struct peer *p)
	{
	}

	int add_routing_table(struct peer *p)
	{
		return 0;
	}
}

BOOST_AUTO_TEST_CASE(number_of_peer)
{
	static const int TEST_FD = 1;

	int peers = get_number_of_peers();
	BOOST_CHECK(peers == 0);

	struct peer *p = alloc_peer(TEST_FD);
	peers = get_number_of_peers();
	BOOST_CHECK(peers == 1);

	free_peer(p);
	peers = get_number_of_peers();
	BOOST_CHECK(peers == 0);
}

