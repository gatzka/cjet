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

#ifndef CJET_LINUX_IO_H
#define CJET_LINUX_IO_H

#include "linux/io_event.h"
#include "peer.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IO_CLOSE -1
#define IO_WOULD_BLOCK -2
#define IO_ERROR -3
#define IO_TOOMUCHDATA -4

struct server {
	struct io_event ev;
};

int run_io(const char *user_name);
ssize_t get_read_ptr(struct peer *p, unsigned int count, const char **read_ptr);
int copy_msg_to_write_buffer(struct peer *p, const void *rendered, uint32_t msg_len_be, size_t already_written);
int handle_all_peer_operations(union io_context *context);
int write_msg(union io_context *context);
int send_buffer(struct peer *p);
int add_io(struct io_event *ev);

#ifdef __cplusplus
}
#endif

#endif
