/*
 * The MIT License (MIT)
 *
 * Copyright (c) <2015> <Stephan Gatzka>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MAIN
#define BOOST_TEST_MODULE peer

#include <boost/test/unit_test.hpp>

#include "log.h"
#include "peer.h"

enum fds {
	TEST_FD = 0,
	ADD_IO_FAILED,
	ADD_ROUTINGTABLE_FAILED,
};

extern "C" {
	int add_io(struct peer *p)
	{
		if (p->io.fd == ADD_IO_FAILED) {
			return -1;
		}
		return 0;
	}

	void remove_io(const struct peer *p)
	{
		(void)p;
		return;
	}

	void remove_all_methods_from_peer(struct peer *p)
	{
		(void)p;
	}

	void remove_all_fetchers_from_peer(struct peer *p)
	{
		(void)p;
	}

	void remove_peer_from_routing_table(const struct peer *p,
		const struct peer *peer_to_remove)
	{
		(void)p;
		(void)peer_to_remove;
	}

	void remove_routing_info_from_peer(const struct peer *p)
	{
		(void)p;
	}

	void remove_all_states_and_methods_from_peer(struct peer *p)
	{
		(void)p;
	}

	void delete_routing_table(struct peer *p)
	{
		(void)p;
	}

	int add_routing_table(struct peer *p)
	{
		if (p->io.fd == ADD_ROUTINGTABLE_FAILED) {
			return -1;
		}
		return 0;
	}
}

static bool peer_in_list(struct list_head *peer_list, struct peer *p)
{
	struct list_head *item;
	struct list_head *tmp;

	list_for_each_safe(item, tmp, peer_list) {
		struct peer *p_in_list = (struct peer *)list_entry(item, struct peer, next_peer);
		if (p == p_in_list) {
			return true;
		}
	}
	return false;
}

static bool starts_with(const char *str, const char *prefix)
{
	size_t lenprefix = ::strlen(prefix);
	size_t lenstr = ::strlen(str);
	return lenstr < lenprefix ? false : ::strncmp(prefix, str, lenprefix) == 0;
}

BOOST_AUTO_TEST_CASE(number_of_peer)
{
	int peers = get_number_of_peers();
	BOOST_CHECK(peers == 0);

	struct peer *p = alloc_peer(TEST_FD);
	peers = get_number_of_peers();
	BOOST_CHECK(peers == 1);

	free_peer(p);
	peers = get_number_of_peers();
	BOOST_CHECK(peers == 0);
}

BOOST_AUTO_TEST_CASE(set_name_of_peer)
{
	struct peer *p = alloc_peer(TEST_FD);
	set_peer_name(p, "name of peer");

	free_peer(p);
	int peers = get_number_of_peers();
	BOOST_CHECK(peers == 0);
}

BOOST_AUTO_TEST_CASE(add_io_failed)
{
	struct peer *p = alloc_peer(ADD_IO_FAILED);
	BOOST_CHECK(p == NULL);
}

BOOST_AUTO_TEST_CASE(add_routingtable_failed)
{
	struct peer *p = alloc_peer(ADD_ROUTINGTABLE_FAILED);
	BOOST_CHECK(p == NULL);
}

BOOST_AUTO_TEST_CASE(destroy_all_peers_test)
{
	static const int PEERS_TO_ALLOCATE = 10;

	int peers = get_number_of_peers();
	BOOST_CHECK(peers == 0);

	for (int i = 0; i < PEERS_TO_ALLOCATE; ++i) {
		alloc_peer(TEST_FD);
	}
	peers = get_number_of_peers();
	BOOST_CHECK(peers == PEERS_TO_ALLOCATE);

	destroy_all_peers();
	peers = get_number_of_peers();
	BOOST_CHECK(peers == 0);
}

BOOST_AUTO_TEST_CASE(check_peer_list)
{
	struct peer *p1 = alloc_peer(TEST_FD);
	struct peer *p2 = alloc_peer(TEST_FD);

	struct list_head *peer_list = get_peer_list();
	BOOST_CHECK(peer_in_list(peer_list, p1) && peer_in_list(peer_list, p2));

	destroy_all_peers();

	peer_list = get_peer_list();
	BOOST_CHECK(!peer_in_list(peer_list, p1) && !peer_in_list(peer_list, p2));
}

BOOST_AUTO_TEST_CASE(log_unknown_peer)
{
	struct peer *p = alloc_peer(TEST_FD);
	log_peer_err(p, "%s", "Hello!");

	char *log_buffer = get_log_buffer();

	BOOST_CHECK(starts_with(log_buffer, "unknown peer"));
	free_peer(p);
}

BOOST_AUTO_TEST_CASE(log_known_peer)
{
	struct peer *p = alloc_peer(TEST_FD);
	set_peer_name(p, "test peer");
	log_peer_err(p, "%s", "Hello!");

	char *log_buffer = get_log_buffer();

	BOOST_CHECK(starts_with(log_buffer, "test peer: "));
	free_peer(p);
}
