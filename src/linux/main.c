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

#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "alloc.h"
#include "authenticate.h"
#include "cmdline_config.h"
#include "generated/version.h"
#include "linux/eventloop_epoll.h"
#include "linux/linux_io.h"
#include "log.h"
#include "parse.h"
#include "table.h"

static int init_random(void)
{
	unsigned int seed;
	FILE* urandom = fopen("/dev/urandom", "r");
	if (urandom == NULL) {
		return -1;
	}

	int ret = -1;
	int len = fread(&seed, 1, sizeof(seed), urandom);
	if (len == sizeof(seed)) {
		srand(seed);
		ret = 0;
	}
	fclose(urandom);
	return ret;
}


int main(int argc, char **argv)
{
	struct cmdline_config config = {
		.run_foreground = false,
		.bind_local_only = false,
		.user_name = NULL,
		.passwd_file = NULL,
		.request_target = "/api/jet/",
	};

	if (init_random() < 0) {
		log_err("Could not initialize random seed!\n");
	}

	init_parser();

	int c;

	while ((c = getopt (argc, argv, "flp:r:u:")) != -1) {
		switch (c) {
			case 'f':
				config.run_foreground = true;
				break;
			case 'l':
				config.bind_local_only = true;
				break;
			case 'p':
				config.passwd_file = optarg;
				break;
			case 'r':
				config.request_target = optarg;
				break;
			case 'u':
				config.user_name = optarg;
				break;
			case '?':
				fprintf(stderr, "Usage: %s [-l] [-f] [-r <request target>] [-u <username>] [-p <password file>]\n", argv[0]);
				return EXIT_FAILURE;
				break;
		}
	}

	if (load_passwd_data(config.passwd_file) < 0) {
		log_err("Cannot load password file!\n");
		return EXIT_FAILURE;
	}

	signal(SIGPIPE, SIG_IGN);

	int ret = EXIT_SUCCESS;
	if ((element_hashtable_create()) == -1) {
		log_err("Cannot allocate hashtable for states!\n");
		ret = EXIT_FAILURE;
		goto element_hashtable_create_failed;
	}

	struct eventloop_epoll eloop = {
		.epoll_fd = 0,
		.loop = {
			.this_ptr = &eloop,
			.init = eventloop_epoll_init,
			.destroy = eventloop_epoll_destroy,
			.run = eventloop_epoll_run,
			.add = eventloop_epoll_add,
			.remove = eventloop_epoll_remove,
		},
	};

	log_info("%s version %s started", CJET_NAME, CJET_VERSION);
	if (run_io(&eloop.loop, &config) < 0) {
		ret = EXIT_FAILURE;
		goto run_io_failed;
	}

	log_info("%s stopped", CJET_NAME);

run_io_failed:
	element_hashtable_delete();
element_hashtable_create_failed:
	free_passwd_data();
	return ret;
}
