#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

#include "state.h"
#include "io.h"

static int shall_close = 0;

static void sighandler(int signum)
{
	(void)signum;
	shall_close = 1;
}

int main()
{
	if (signal(SIGTERM, sighandler) == SIG_ERR) {
		fprintf(stderr, "signal failed!\n");
		return EXIT_FAILURE;
	}
	if (signal(SIGINT, sighandler) == SIG_ERR) {
		fprintf(stderr, "signal failed!\n");
		goto signal_failed;
	}

	if ((create_setter_hashtable()) == -1) {
		fprintf(stderr, "Cannot allocate hashtable for states!\n");
		goto create_setter_hashtable_failed;
	}

	if (run_io(&shall_close) < 0) {
		goto run_io_failed;
	}

	delete_setter_hashtable();
	signal(SIGINT, SIG_DFL);
	signal(SIGTERM, SIG_DFL);
	return EXIT_SUCCESS;

run_io_failed:
	delete_setter_hashtable();
create_setter_hashtable_failed:
	signal(SIGINT, SIG_DFL);
signal_failed:
	signal(SIGTERM, SIG_DFL);
	return EXIT_FAILURE;
}
