#ifndef CJET_LINUX_CONFIG_H
#define CJET_LINUX_CONFIG_H

enum {CONFIG_SERVER_PORT = 11122};
enum {CONFIG_LISTEN_BACKLOG = 40};

enum {CONFIG_CHECK_JSON_LENGTH = 0};

/*
 * It is somehow beneficial if this size is 32 bit aligned.
 */
enum {CONFIG_MAX_MESSAGE_SIZE = 512};
enum {CONFIG_MAX_WRITE_BUFFER_SIZE = 5120};

/*
 * This parameter configures the maximum amount of states that can be
 * handled in a jet. The number of states is 2^STATE_TABLE_ORDER.
 */
enum {CONFIG_STATE_TABLE_ORDER = 13};

/*
 * This parameter configures the maximum ongoing routed messages per
 * peer.
 */
enum {CONFIG_ROUTING_TABLE_ORDER = 6};

enum {CONFIG_MAX_NUMBER_OF_PEERS = 10};

enum {CONFIG_MAX_FETCHES_PER_STATE = 2};

/* Linux specific configs */

enum {CONFIG_MAX_EPOLL_EVENTS = CONFIG_MAX_NUMBER_OF_PEERS + 1};

#endif
