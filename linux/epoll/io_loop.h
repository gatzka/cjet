#ifndef CJET_IO_LOOP_H
#define CJET_IO_LOOP_H

int add_epoll(int fd, int epoll_fd, void *cookie);
void remove_epoll(int fd, int epoll_fd);

#endif

