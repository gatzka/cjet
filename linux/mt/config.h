#ifndef CJET_LINUX_CONFIG_H
#define CJET_LINUX_CONFIG_H

enum {SERVER_PORT = 11122};
enum {LISTEN_BACKLOG = 40};

enum {CONFIG_CHECK_JSON_LENGTH = 0};

/*
 * It is somehow beneficial if this size is 32 bit aligned.
 */
enum {MAX_MESSAGE_SIZE = 512};
enum {WRITE_BUFFER_CHUNK = 512};
enum {MAX_WRITE_BUFFER_SIZE = 10 * WRITE_BUFFER_CHUNK};

/*
 * This config parameter the maximum amount of states that can be
 * handled in a jet. The number of states is 2^STATE_TABLE_ORDER.
 */
enum {STATE_TABLE_ORDER = 13};
enum {MAX_NUMBER_OF_PEERS = 10};

#endif
