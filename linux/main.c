#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

#include "io.h"
#include "state.h"

int main()
{
	signal(SIGPIPE, SIG_IGN);

	if ((create_state_hashtable()) == -1) {
		fprintf(stderr, "Cannot allocate hashtable for states!\n");
		return EXIT_FAILURE;
	}

	if (run_io() < 0) {
		goto run_io_failed;
	}

	delete_state_hashtable();
	return EXIT_SUCCESS;

run_io_failed:
	delete_state_hashtable();
	return EXIT_FAILURE;
}
