/*
 *The MIT License (MIT)
 *
 * Copyright (c) <2017> <Stephan Gatzka>
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

#include <stdarg.h>
#include <stdio.h>
#include <syslog.h>

#include "compiler.h"
#include "log.h"

static char log_buffer[200];

__attribute__((format(printf, 1, 2)))
void log_err(const char *format, ...)
{
	va_list args;
	va_start(args, format);
	vsnprintf(log_buffer, sizeof(log_buffer), format, args);
    printf("LOG_ERR, %s\n", log_buffer);
	va_end(args);
}

__attribute__((format(printf, 1, 2)))
void log_warn(const char *format, ...)
{
	va_list args;
	va_start(args, format);
	vsnprintf(log_buffer, sizeof(log_buffer), format, args);
    printf("LOG_WARNING, %s\n", log_buffer);
	va_end(args);
}

__attribute__((format(printf, 1, 2)))
void log_info(const char *format, ...)
{
	va_list args;
	va_start(args, format);
	vsnprintf(log_buffer, sizeof(log_buffer), format, args);
    printf("LOG_INFO, %s\n", log_buffer);
	va_end(args);
}
