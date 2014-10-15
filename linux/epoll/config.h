#ifndef CJET_LINUX_CONFIG_H
#define CJET_LINUX_CONFIG_H

enum {CONFIG_SERVER_PORT = 11122};
enum {CONFIG_LISTEN_BACKLOG = 40};

enum {CONFIG_CHECK_JSON_LENGTH = 0};
/*
 * It is somehow beneficial if this size is 32 bit aligned.
 */
enum {CONFIG_MAX_MESSAGE_SIZE = 512};
enum {CONFIG_WRITE_BUFFER_CHUNK = 512};
enum {CONFIG_MAX_WRITE_BUFFER_SIZE = 10 * CONFIG_WRITE_BUFFER_CHUNK};

/*
 * This config parameter the maximum amount of states that can be
 * handled in a jet. The number of states is 2^STATE_TABLE_ORDER.
 */
enum {CONFIG_STATE_TABLE_ORDER = 13};
enum {CONFIG_MAX_NUMBER_OF_PEERS = 10};

/* Linux specific configs */

enum {CONFIG_MAX_EPOLL_EVENTS = CONFIG_MAX_NUMBER_OF_PEERS + 1};

#endif
