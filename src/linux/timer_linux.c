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

#include <fcntl.h>
#include <math.h>
#include <string.h>
#include <sys/timerfd.h>

#include "compiler.h"
#include "eventloop.h"
#include "socket.h"
#include "timer.h"
#include "util.h"

static const unsigned long NSECONDS_IN_SECONDS = 1000000000;

static struct itimerspec convert_timeoutns_to_itimerspec(uint64_t timeout)
{
	struct itimerspec ts;
	time_t seconds = timeout / NSECONDS_IN_SECONDS;
	long nanos = timeout - (seconds * NSECONDS_IN_SECONDS);

	ts.it_interval.tv_sec = 0;
	ts.it_interval.tv_nsec = 0;
	ts.it_value.tv_sec = seconds;
	ts.it_value.tv_nsec = nanos;
	return ts;
}

static enum eventloop_return timer_read(struct io_event *ev)
{
	struct cjet_timer *timer = container_of(ev, struct cjet_timer, ev);

	uint64_t number_of_expirations;
	int ret = socket_read(ev->sock, &number_of_expirations, sizeof(number_of_expirations));
	if (likely(ret == sizeof(number_of_expirations))) {
		timer->handler(timer->handler_context, false);
	} else {
	// TODO: maybe call registered callback with an error parameter
	}

	return EL_CONTINUE_LOOP;
}

static enum eventloop_return timer_error(struct io_event *ev)
{
	// TODO: maybe call registered callback with error parameter
	(void)ev;
	return EL_CONTINUE_LOOP;
}

static int timer_start(void *this_ptr, uint64_t timeout_ns, timer_handler handler, void *handler_context)
{
	struct cjet_timer *timer = (struct cjet_timer *)this_ptr;
	timer->handler = handler;
	timer->handler_context = handler_context;


	struct itimerspec timeout = convert_timeoutns_to_itimerspec(timeout_ns);
	return timerfd_settime(timer->ev.sock, 0, &timeout, NULL);
}

static int timer_cancel(void *this_ptr)
{
	struct cjet_timer *timer = (struct cjet_timer *)this_ptr;
	static struct itimerspec timeout;
	memset(&timeout, 0x0, sizeof(timeout));

	int ret = timerfd_settime(timer->ev.sock, 0, &timeout, NULL);
	if (likely(ret == 0)) {
		timer->handler(timer->handler_context, true);
	} else {
		// TODO: maybe call registered callback with error parameter
	}

	return ret;
}

int cjet_timer_init(struct cjet_timer *timer, struct eventloop *loop)
{
	timer->ev.loop = loop;
	int ret = timerfd_create(CLOCK_MONOTONIC, O_NONBLOCK);
	if (unlikely(ret == -1)) {
		return -1;
	}

	timer->ev.sock = (socket_type)ret;
	timer->ev.read_function = timer_read;
	timer->ev.write_function = NULL;
	timer->ev.error_function = timer_error;

	timer->start = timer_start;
	timer->cancel = timer_cancel;

	enum eventloop_return ev_ret = timer->ev.loop->add(timer->ev.loop->this_ptr, &timer->ev);
	if (unlikely(ev_ret == EL_ABORT_LOOP)) {
		return -1;
	} else {
		return 0;
	}
}

void cjet_timer_destroy(struct cjet_timer *timer)
{
	timer->ev.loop->remove(timer->ev.loop, &timer->ev);
	socket_close(timer->ev.sock);
}
