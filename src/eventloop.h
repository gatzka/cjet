/*
 *The MIT License (MIT)
 *
 * Copyright (c) <2016> <Stephan Gatzka>
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

#ifndef CJET_LINUX_EVENTLOOP_H
#define CJET_LINUX_EVENTLOOP_H

#ifdef __cplusplus
extern "C" {
#endif

#include "generated/os_config.h"

/**
 * @brief The eventloop_return enum defines the allowed return values of eventloop callback functions.
 */
enum eventloop_return {
	EL_ABORT_LOOP,    /**< The eventloop will be aborted. */
	EL_CONTINUE_LOOP, /**< The eventloop will continue to run. */
	EL_EVENT_REMOVED, /**< The event was removed from the eventloop in the callback.
	                    The eventloop will continue but will not process further events on the signaled IO channel. */
};

struct eventloop;
struct io_event;

typedef enum eventloop_return (*eventloop_function)(struct io_event *ev);

struct io_event {
	socket_type sock;
	eventloop_function read_function;
	eventloop_function write_function;
	eventloop_function error_function;
	struct eventloop *loop;
};

struct eventloop {
	void *this_ptr;
	int (*init)(void *this_ptr);
	void (*destroy)(const void *this_ptr);
	int (*run)(void *this_ptr, const int *go_ahead);
	enum eventloop_return (*add)(const void *this_ptr, const struct io_event *ev);
	void (*remove)(void *this_ptr, const struct io_event *ev);
};

#ifdef __cplusplus
}
#endif

#endif
