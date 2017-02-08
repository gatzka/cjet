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

#ifndef CJET_LOG_H
#define CJET_LOG_H

#ifdef TESTING

#ifdef __cplusplus
extern "C" {
#endif

void test_log(const char *format, ...);
char *get_log_buffer(void);

#ifdef __cplusplus
}
#endif

#define log_err(...) test_log(__VA_ARGS__)
#define log_warn(...) test_log(__VA_ARGS__)
#define log_info(...) test_log(__VA_ARGS__)

#else

#if defined(_MSC_VER)
#include "windows/syslog/syslog.h"
#else
#include <syslog.h>
#endif

#define log_err(...) syslog(LOG_ERR, __VA_ARGS__)
#define log_warn(...) syslog(LOG_WARNING, __VA_ARGS__)
#define log_info(...) syslog(LOG_INFO, __VA_ARGS__)

#endif

#endif
