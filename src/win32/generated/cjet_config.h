/*
 *The MIT License (MIT)
 *
 * Copyright (c) <2014> <Stephan Gatzka>
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

#ifndef CJET_CONFIG_H
#define CJET_CONFIG_H

#include <stdbool.h>
#include <stddef.h>

enum {CONFIG_JET_PORT = 11122};
enum {CONFIG_JETWS_PORT = 11123};
enum {CONFIG_LISTEN_BACKLOG = 40};

enum {CONFIG_CHECK_JSON_LENGTH = 0};

/*
 * It is somehow beneficial if this size is 32 bit aligned.
 */
enum {CONFIG_MAX_MESSAGE_SIZE = 512};
enum {CONFIG_MAX_WRITE_BUFFER_SIZE = 5120};

/*
 * This parameter configures the maximum amount of states that can be
 * handled in a jet. The number of states is 2^ELEMENT_TABLE_ORDER.
 */
enum {CONFIG_ELEMENT_TABLE_ORDER = 13};

/*
 * This parameter configures the maximum ongoing routed messages per
 * peer.
 */
enum {CONFIG_ROUTING_TABLE_ORDER = 6};

enum {CONFIG_INITIAL_FETCH_TABLE_SIZE = 4};

/*
 * This parameter configures the default timeout of routed messages if
 * not specified otherwise.
 */
static const double CONFIG_ROUTED_MESSAGES_TIMEOUT = 5.0;

/*
 * This parameter configures how many matchers are allowed in a single fetch expression.
 */
enum {CONFIG_MAX_NUMBERS_OF_MATCHERS_IN_FETCH = 12};

/*
 * This parameter configures if "add" of states or methods is only allowed from localhost peers.
 */
static const bool CONFIG_ALLOW_ADD_ONLY_FROM_LOCALHOST = false;

/*
 * This parameter configures how much memory cjet might allocate from heap
 */
static const size_t CONFIG_MAX_HEAPSIZE_IN_KBYTE = 20480;

#endif
