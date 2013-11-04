/******************************************************************************
* Copyright (C) 1994-2013 Lua.org, PUC-Rio.
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
* MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
* IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
* CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
* TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
* SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
******************************************************************************/

#include <assert.h>
#include <ctype.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "lmatch.h"

#define uchar(c)    ((unsigned char)(c))
#define LUA_MAXCAPTURES     32
#define MAXCCALLS   200
#define CAP_UNFINISHED  (-1)
#define CAP_POSITION    (-2)


#define SPECIALS    "^$*+?.-"

typedef struct MatchState {
	int matchdepth;  /* control for recursive depth (to avoid C stack overflow) */
	const char *src_init;  /* init of source string */
	const char *src_end;  /* end ('\0') of source string */
	const char *p_end;  /* end ('\0') of pattern */
} MatchState;

static const char *lmemfind(const char *s1, size_t l1, const char *s2, size_t l2)
{
	if (l2 == 0)
		return s1;  /* empty strings are everywhere */
	else if (l2 > l1)
		return NULL;  /* avoids a negative `l1' */
	else {
		const char *init;  /* to search for a `*s2' inside `s1' */
		l2--;  /* 1st char will be checked by `memchr' */
		l1 = l1 - l2;  /* `s2' cannot be found after that */
		while (l1 > 0 && (init = (const char *)memchr(s1, *s2, l1)) != NULL) {
			init++;   /* 1st char is already checked */
			if (memcmp(init, s2 + 1, l2) == 0)
				return init - 1;
			else {  /* correct `l1' and `s1' to try again */
				l1 -= init - s1;
				s1 = init;
			}
		}
		return NULL;  /* not found */
	}
}

static int nospecials(const char *p)
{
	if (strpbrk(p, SPECIALS))
		return 0;
	else
		return 1;
}

static const char *match(MatchState *ms, const char *s, const char *p);

static int singlematch(MatchState *ms, const char *s, const char *p)
{
	if (s >= ms->src_end)
		return 0;
	else {
		int c = uchar(*s);
		switch (*p) {
			case '.': return 1;  /* matches any char */
			default:  return (uchar(*p) == c);
		}
	}
}

static const char *max_expand(MatchState *ms, const char *s, const char *p, const char *ep)
{
	ptrdiff_t i = 0;  /* counts maximum expand for item */
	while (singlematch(ms, s + i, p))
		i++;
	/* keeps trying to match with the maximum repetitions */
	while (i>=0) {
		const char *res = match(ms, (s+i), ep+1);
		if (res) return res;
		i--;  /* else didn't match; reduce 1 repetition to try again */
	}
	return NULL;
}

static const char *min_expand(MatchState *ms, const char *s, const char *p, const char *ep)
{
	for (;;) {
		const char *res = match(ms, s, ep+1);
		if (res != NULL)
			return res;
		else if (singlematch(ms, s, p))
			s++;  /* try with one more repetition */
		else return NULL;
	}
}

static const char *match(MatchState *ms, const char *s, const char *p)
{
	if (ms->matchdepth-- == 0)
		printf("pattern too complex");
init: /* using goto's to optimize tail recursion */
	if (p != ms->p_end) {  /* end of pattern? */
		switch (*p) {
			case '$': {
						  if ((p + 1) != ms->p_end)  /* is the `$' the last char in pattern? */
							  goto dflt;  /* no; go to default */
						  s = (s == ms->src_end) ? s : NULL;  /* check end of string */
						  break;
					  }
			default: dflt: {  /* pattern class plus optional suffix */
						 const char *ep = p;  /* points to optional suffix */
						 ep++;
						 /* does not match at least once? */
						 if (!singlematch(ms, s, p)) {
							 if (*ep == '*' || *ep == '?' || *ep == '-') {  /* accept empty? */
								 p = ep + 1; goto init;  /* return match(ms, s, ep + 1); */
							 }
							 else  /* '+' or no suffix */
								 s = NULL;  /* fail */
						 }
						 else {  /* matched once */
							 switch (*ep) {  /* handle optional suffix */
								 case '?': {  /* optional */
											   const char *res;
											   if ((res = match(ms, s + 1, ep + 1)) != NULL)
												   s = res;
											   else {
												   p = ep + 1; goto init;  /* else return match(ms, s, ep + 1); */
											   }
											   break;
										   }
								 case '+':  /* 1 or more repetitions */
										   s++;  /* 1 match already done */
										   /* go through */
								 case '*':  /* 0 or more repetitions */
										   s = max_expand(ms, s, p, ep);
										   break;
								 case '-':  /* 0 or more repetitions (minimum) */
										   s = min_expand(ms, s, p, ep);
										   break;
								 default:  /* no suffix */
										   s++; p = ep; goto init;  /* return match(ms, s + 1, ep); */
							 }
						 }
						 break;
					 }
		}
	}
	ms->matchdepth++;
	return s;
}

int str_find_aux(const char *s, const char *p)
{
	size_t ls = strlen(s);
	size_t lp = strlen(p);

	/* explicit request or no special characters? */
	if (nospecials(p)) {
		/* do a plain search */
		const char *s2 = lmemfind(s, ls, p, lp);
		if (s2) {
			return 1;
		}
	} else {
		MatchState ms;
		int anchor = (*p == '^');
		if (anchor) {
			p++; lp--;  /* skip anchor character */
		}
		ms.matchdepth = MAXCCALLS;
		ms.src_init = s;
		ms.src_end = s + ls;
		ms.p_end = p + lp;
		do {
			const char *res;
			assert(ms.matchdepth == MAXCCALLS);
			if ((res = match(&ms, s, p)) != NULL) {
				return 1;
			}
		} while (s++ < ms.src_end && !anchor);
	}
	return 0;
}
