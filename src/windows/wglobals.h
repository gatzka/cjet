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

#ifndef CJET_WGLOBALS_H
#define CJET_WGLOBALS_H

#ifdef __cplusplus
extern "C" {
#endif


#define SIGPIPE         13

#define	F_GETFL			3
#define	F_SETFL			4		

#define SOL_TCP         6

#define TCP_KEEPCNT		20
#define TCP_KEEPIDLE	180
#define TCP_KEEPINTVL	60

#define	O_NONBLOCK		0x0004		/* no delay */

#ifdef __cplusplus
}
#endif

#endif