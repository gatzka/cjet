#ifndef CJET_LINUX_CONFIG_H
#define CJET_LINUX_CONFIG_H

#define SERVER_PORT	11122
#define LISTEN_BACKLOG 40

static const unsigned int CONFIG_CHECK_JSON_LENGTH = 0;
/*
 * It is somehow beneficial if this size is 32 bit aligned.
 */
#define MAX_MESSAGE_SIZE 512
#define WRITE_BUFFER_CHUNK 512
#define MAX_WRITE_BUFFER_SIZE (10 * (WRITE_BUFFER_CHUNK))

/*
 * This config parameter the maximum amount of states that can be
 * handled in a jet. The number of states is 2^STATE_TABLE_ORDER.
 */
#define STATE_TABLE_ORDER 13

#define MAX_NUMBER_OF_PEERS 10

/* Linux specific configs */

#define MAX_EPOLL_EVENTS (MAX_NUMBER_OF_PEERS + 1)

#endif
