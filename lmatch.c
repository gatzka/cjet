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

#define L_ESC       '%'
#define SPECIALS    "^$*+?.([%-"

typedef struct MatchState {
	int matchdepth;  /* control for recursive depth (to avoid C stack overflow) */
	const char *src_init;  /* init of source string */
	const char *src_end;  /* end ('\0') of source string */
	const char *p_end;  /* end ('\0') of pattern */
	int level;  /* total number of captures (finished or unfinished) */
	struct {
		const char *init;
		ptrdiff_t len;
	} capture[LUA_MAXCAPTURES];
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

#if 0
static int nospecials(const char *p, size_t l) {
	size_t upto = 0;
	do {
		if (strpbrk(p + upto, SPECIALS))
			return 0;  /* pattern has a special character */
		upto += strlen(p + upto) + 1;  /* may have more after \0 */
	} while (upto <= l);
	return 1;  /* no special chars found */
}
#endif

static const char *match(MatchState *ms, const char *s, const char *p);

static int capture_to_close(MatchState *ms)
{
	int level = ms->level;
	for (level--; level>=0; level--)
		if (ms->capture[level].len == CAP_UNFINISHED) return level;
	printf("invalid pattern capture");
	return 0;
}

static const char *start_capture(MatchState *ms, const char *s,	const char *p, int what)
{
	const char *res;
	int level = ms->level;
	if (level >= LUA_MAXCAPTURES) printf("too many captures");
	ms->capture[level].init = s;
	ms->capture[level].len = what;
	ms->level = level+1;
	if ((res=match(ms, s, p)) == NULL)  /* match failed? */
		ms->level--;  /* undo capture */
	return res;
}

static const char *end_capture (MatchState *ms, const char *s, const char *p)
{
	int l = capture_to_close(ms);
	const char *res;
	ms->capture[l].len = s - ms->capture[l].init;  /* close capture */
	if ((res = match(ms, s, p)) == NULL)  /* match failed? */
		ms->capture[l].len = CAP_UNFINISHED;  /* undo capture */
	return res;
}

static const char *matchbalance(MatchState *ms, const char *s,	const char *p)
{
	if (p >= ms->p_end - 1)
		printf("malformed pattern (missing arguments\n");
	if (*s != *p) return NULL;
	else {
		int b = *p;
		int e = *(p+1);
		int cont = 1;
		while (++s < ms->src_end) {
			if (*s == e) {
				if (--cont == 0) return s+1;
			}
			else if (*s == b) cont++;
		}
	}
	return NULL;  /* string ends out of balance */
}

static const char *classend(MatchState *ms, const char *p)
{
	switch (*p++) {
		case L_ESC: {
						if (p == ms->p_end)
							printf("malformed pattern (ends with )\n");
						return p+1;
					}
		case '[': {
					  if (*p == '^') p++;
					  do {  /* look for a `]' */
						  if (p == ms->p_end)
							  printf("malformed pattern (missing ]\n");
						  if (*(p++) == L_ESC && p < ms->p_end)
							  p++;  /* skip escapes (e.g. `%]') */
					  } while (*p != ']');
					  return p+1;
				  }
		default: {
					 return p;
				 }
	}
}

static int check_capture(MatchState *ms, int l)
{
	l -= '1';
	if (l < 0 || l >= ms->level || ms->capture[l].len == CAP_UNFINISHED)
		printf("invalid capture index %d\n", l + 1);
		return 0;
	return l;
}

static const char *match_capture(MatchState *ms, const char *s, int l)
{
	size_t len;
	l = check_capture(ms, l);
	len = ms->capture[l].len;
	if ((size_t)(ms->src_end-s) >= len &&
			memcmp(ms->capture[l].init, s, len) == 0)
		return s+len;
	else return NULL;
}

static int match_class(int c, int cl)
{
	int res;
	switch (tolower(cl)) {
		case 'a' : res = isalpha(c); break;
		case 'c' : res = iscntrl(c); break;
		case 'd' : res = isdigit(c); break;
		case 'g' : res = isgraph(c); break;
		case 'l' : res = islower(c); break;
		case 'p' : res = ispunct(c); break;
		case 's' : res = isspace(c); break;
		case 'u' : res = isupper(c); break;
		case 'w' : res = isalnum(c); break;
		case 'x' : res = isxdigit(c); break;
		case 'z' : res = (c == 0); break;  /* deprecated option */
		default: return (cl == c);
	}
	return (islower(cl) ? res : !res);
}

static int matchbracketclass(int c, const char *p, const char *ec)
{
	int sig = 1;
	if (*(p+1) == '^') {
		sig = 0;
		p++;  /* skip the `^' */
	}
	while (++p < ec) {
		if (*p == L_ESC) {
			p++;
			if (match_class(c, uchar(*p)))
				return sig;
		}
		else if ((*(p+1) == '-') && (p+2 < ec)) {
			p+=2;
			if (uchar(*(p-2)) <= c && c <= uchar(*p))
				return sig;
		}
		else if (uchar(*p) == c) return sig;
	}
	return !sig;
}

static int singlematch(MatchState *ms, const char *s, const char *p, const char *ep)
{
	if (s >= ms->src_end)
		return 0;
	else {
		int c = uchar(*s);
		switch (*p) {
			case '.': return 1;  /* matches any char */
			case L_ESC: return match_class(c, uchar(*(p+1)));
			case '[': return matchbracketclass(c, p, ep-1);
			default:  return (uchar(*p) == c);
		}
	}
}

static const char *max_expand(MatchState *ms, const char *s, const char *p, const char *ep)
{
	ptrdiff_t i = 0;  /* counts maximum expand for item */
	while (singlematch(ms, s + i, p, ep))
		i++;
	/* keeps trying to match with the maximum repetitions */
	while (i>=0) {
		const char *res = match(ms, (s+i), ep+1);
		if (res) return res;
		i--;  /* else didn't match; reduce 1 repetition to try again */
	}
	return NULL;
}

static const char *min_expand (MatchState *ms, const char *s, const char *p, const char *ep)
{
	for (;;) {
		const char *res = match(ms, s, ep+1);
		if (res != NULL)
			return res;
		else if (singlematch(ms, s, p, ep))
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
			case '(': {  /* start capture */
						  if (*(p + 1) == ')')  /* position capture? */
							  s = start_capture(ms, s, p + 2, CAP_POSITION);
						  else
							  s = start_capture(ms, s, p + 1, CAP_UNFINISHED);
						  break;
					  }
			case ')': {  /* end capture */
						  s = end_capture(ms, s, p + 1);
						  break;
					  }
			case '$': {
						  if ((p + 1) != ms->p_end)  /* is the `$' the last char in pattern? */
							  goto dflt;  /* no; go to default */
						  s = (s == ms->src_end) ? s : NULL;  /* check end of string */
						  break;
					  }
			case L_ESC: {  /* escaped sequences not in the format class[*+?-]? */
							switch (*(p + 1)) {
								case 'b': {  /* balanced string? */
											  s = matchbalance(ms, s, p + 2);
											  if (s != NULL) {
												  p += 4; goto init;  /* return match(ms, s, p + 4); */
											  }  /* else fail (s == NULL) */
											  break;
										  }
								case 'f': {  /* frontier? */
											  const char *ep; char previous;
											  p += 2;
											  if (*p != '[')
												  printf("missing [ after f in pattern\n");
											  ep = classend(ms, p);  /* points to what is next */
											  previous = (s == ms->src_init) ? '\0' : *(s - 1);
											  if (!matchbracketclass(uchar(previous), p, ep - 1) &&
													  matchbracketclass(uchar(*s), p, ep - 1)) {
												  p = ep; goto init;  /* return match(ms, s, ep); */
											  }
											  s = NULL;  /* match failed */
											  break;
										  }
								case '0': case '1': case '2': case '3':
								case '4': case '5': case '6': case '7':
								case '8': case '9': {  /* capture results (%0-%9)? */
														s = match_capture(ms, s, uchar(*(p + 1)));
														if (s != NULL) {
															p += 2; goto init;  /* return match(ms, s, p + 2) */
														}
														break;
													}
								default: goto dflt;
							}
							break;
						}
			default: dflt: {  /* pattern class plus optional suffix */
						 const char *ep = classend(ms, p);  /* points to optional suffix */
						 /* does not match at least once? */
						 if (!singlematch(ms, s, p, ep)) {
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
			ms.level = 0;
			assert(ms.matchdepth == MAXCCALLS);
			if ((res = match(&ms, s, p)) != NULL) {
				return 1;
			}
		} while (s++ < ms.src_end && !anchor);
	}
	return 0;
}
