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

#include <errno.h>
#include <sys/epoll.h>
#include <string.h>
#include <unistd.h>

#include "compiler.h"
#include "eventloop.h"
#include "generated/os_config.h"
#include "linux/eventloop_epoll.h"
#include "log.h"

static int epoll_fd;

static enum callback_return handle_events(int num_events, struct epoll_event *events)
{
	if (unlikely(num_events == -1)) {
		if (errno == EINTR) {
			return CONTINUE_LOOP;
		} else {
			return ABORT_LOOP;
		}
	}
	for (int i = 0; i < num_events; ++i) {
		struct io_event *ev = events[i].data.ptr;

		if (unlikely((events[i].events & ~(EPOLLIN | EPOLLOUT)) != 0)) {
			if (ev->error_function(ev) == ABORT_LOOP) {
				return ABORT_LOOP;
			}
		} else {
			if (events[i].events & EPOLLIN) {
				if (likely(ev->read_function != NULL)) {
					enum callback_return ret = ev->read_function(ev);
					if (unlikely(ret == ABORT_LOOP)) {
						return ABORT_LOOP;
					}
					if (unlikely(ret == IO_REMOVED)) {
						continue;
					}
				}
			}
			if (events[i].events & EPOLLOUT) {
				if (likely(ev->write_function != NULL)) {
					enum callback_return ret = ev->write_function(ev);
					if (unlikely(ret == ABORT_LOOP)) {
						return ABORT_LOOP;
					}
					if (unlikely(ret == IO_REMOVED)) {
						continue;
					}
				}
			}
		}
	}
	return CONTINUE_LOOP;
}

int eventloop_epoll_create(void)
{
	epoll_fd = epoll_create(1);
	if (epoll_fd < 0) {
		return -1;
	}
	return 0;
}

void eventloop_epoll_destroy(void)
{
	close(epoll_fd);
}

int eventloop_epoll_run(int *go_ahead)
{
	struct epoll_event events[CONFIG_MAX_EPOLL_EVENTS];

	while (likely(*go_ahead)) {
		int num_events =
			epoll_wait(epoll_fd, events, CONFIG_MAX_EPOLL_EVENTS, -1);

		if (unlikely(handle_events(num_events, events) == ABORT_LOOP)) {
			return -1;
			break;
		}
	}
	return 0;
}

enum callback_return eventloop_epoll_add(struct io_event *ev)
{
	struct epoll_event epoll_ev;

	memset(&epoll_ev, 0, sizeof(epoll_ev));
	epoll_ev.data.ptr = ev;
	epoll_ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
	if (unlikely(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ev->sock, &epoll_ev) < 0)) {
		log_err("epoll_ctl failed!\n");
		return ABORT_LOOP;
	}
	return CONTINUE_LOOP;
}

void eventloop_epoll_remove(struct io_event *ev)
{
	epoll_ctl(epoll_fd, EPOLL_CTL_DEL, ev->sock, NULL);
}

