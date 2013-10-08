#ifndef CJET_CONFIG_H
#define CJET_CONFIG_H

#define SERVER_PORT 7899
#define LISTEN_BACKLOG 40

/* must be a power of 2 */
#define MAX_MESSAGE_SIZE 128


/* Linux specific configs */
#define MAX_EPOLL_EVENTS 100

#endif
