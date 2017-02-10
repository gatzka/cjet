/*
*The MIT License (MIT)
*
* Copyright (c) <2017> <Mathieu Borchardt>
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

#include <Windows.h>
#include <wincrypt.h>
#include <stdio.h>

#include "jet_random.h"


static HCRYPTPROV prov = NULL;

int init_random(void)
{
	int isSuccess = -1;

	if (prov == NULL)
	{
		if (CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL, 0))
		{
			isSuccess = 0;
		}
	}

	return isSuccess;
}

void close_random(void)
{
	int isSuccess = -1;

	if (prov != NULL)
	{
		if (CryptReleaseContext(prov, 0))
		{
			isSuccess = 0;
		}
	}

	return isSuccess;
}

void cjet_get_random_bytes(void *bytes, size_t num_bytes)
{
	long int li = 0;
	if (CryptGenRandom(prov, sizeof(li), (BYTE *)&li))
	{
		printf("Random number: %ld\n", li);
	}
	else
	{
		/* Handle error */
	}
	(void)li;
}