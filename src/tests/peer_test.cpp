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

struct peer *alloc_peer()
{
	struct peer *p = (struct peer *)::malloc(sizeof(*p));
	int ret = init_peer(p, false);
	if (ret != 0) {
		free(p);
		p = NULL;
	}
	return p;
}

void close_peer(struct peer *p)
{
	free_peer_resources(p);
}

void free_peer(struct peer *p)
{
	close_peer(p);
	::free(p);
}

static bool peer_in_list(const struct list_head *peer_list, struct peer *p)
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

	struct peer *p = alloc_peer();
	peers = get_number_of_peers();
	BOOST_CHECK(peers == 1);

	free_peer(p);
	peers = get_number_of_peers();
	BOOST_CHECK(peers == 0);
}

BOOST_AUTO_TEST_CASE(set_name_of_peer)
{
	struct peer *p = alloc_peer();
	set_peer_name(p, "name of peer");

	free_peer(p);
	int peers = get_number_of_peers();
	BOOST_CHECK(peers == 0);
}

BOOST_AUTO_TEST_CASE(destroy_all_peers_test)
{
	static const int PEERS_TO_ALLOCATE = 10;
	
	struct peer *peer_array[PEERS_TO_ALLOCATE];

	int peers = get_number_of_peers();
	BOOST_CHECK(peers == 0);

	for (int i = 0; i < PEERS_TO_ALLOCATE; ++i) {
		struct peer *p = alloc_peer();
		p->close = close_peer;
		peer_array[i] = p;
	}
	peers = get_number_of_peers();
	BOOST_CHECK(peers == PEERS_TO_ALLOCATE);

	destroy_all_peers();
	peers = get_number_of_peers();
	BOOST_CHECK(peers == 0);
	
	for (int i = 0; i < PEERS_TO_ALLOCATE; ++i) {
		::free(peer_array[i]);
	}
}

BOOST_AUTO_TEST_CASE(check_peer_list)
{
	struct peer *p1 = alloc_peer();
	p1->close = close_peer;
	struct peer *p2 = alloc_peer();
	p2->close = close_peer;

	const struct list_head *peer_list = get_peer_list();
	BOOST_CHECK(peer_in_list(peer_list, p1) && peer_in_list(peer_list, p2));

	destroy_all_peers();

	peer_list = get_peer_list();
	BOOST_CHECK(!peer_in_list(peer_list, p1) && !peer_in_list(peer_list, p2));

	::free(p1);
	::free(p2);
}

BOOST_AUTO_TEST_CASE(log_unknown_peer)
{
	struct peer *p = alloc_peer();
	log_peer_err(p, "%s", "Hello!");

	char *log_buffer = get_log_buffer();

	BOOST_CHECK(starts_with(log_buffer, "unknown peer"));
	free_peer(p);
}

BOOST_AUTO_TEST_CASE(log_known_peer)
{
	struct peer *p = alloc_peer();
	set_peer_name(p, "test peer");
	log_peer_err(p, "%s", "Hello!");

	char *log_buffer = get_log_buffer();

	BOOST_CHECK(starts_with(log_buffer, "test peer: "));
	free_peer(p);
}
