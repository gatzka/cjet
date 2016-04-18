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

#include <stdint.h>

enum callback_return {ABORT_LOOP = -1, CONTINUE_LOOP = 0};

union io_context {
	void *ptr;
	int fd;
	uint32_t u32;
	uint64_t u64;
};

struct io_event {
	union io_context context;
	enum callback_return (*read_function)(union io_context*);
	enum callback_return (*write_function)(union io_context*);
	enum callback_return (*error_function)(union io_context*);
};

int eventloop_create(void);
void eventloop_destroy(void);
int eventloop_run(int *go_ahead);
enum callback_return eventloop_add_io(struct io_event *ev);
void eventloop_remove_io(struct io_event *ev);

#ifdef __cplusplus
}
#endif

#endif

