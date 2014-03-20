#include <arpa/inet.h>
#include <endian.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static const unsigned int MIN_MESSAGE_SIZE = 10;
static const unsigned int MAX_MESSAGE_SIZE = 900;

static const unsigned int ROUNDS = 100000;

static const char ip[] = "127.0.0.1";
//static const char ip[] = "172.19.191.19";
//static const char ip[] = "172.19.204.22";

int main()
{
	struct sockaddr_in serv_addr;
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = inet_addr(ip);
	serv_addr.sin_port = htons(11122);

	int fd = socket(AF_INET, SOCK_STREAM, 0);

	static const int tcp_nodelay_on = 1;
	if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &tcp_nodelay_on, sizeof(tcp_nodelay_on)) < 0) {
		fprintf(stderr, "Could not set TCP_NODELAY\n");
		return EXIT_FAILURE;
	}

	if (connect(fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
		fprintf(stderr, "Failed to connect with server\n");
		return EXIT_FAILURE;
	}

	fprintf(stdout, "MSGSIZE time\n");
	fflush(stdout);

	uint32_t i;
	for (i = MIN_MESSAGE_SIZE; i <= MAX_MESSAGE_SIZE; i++) {
		struct timespec begin;
		struct timespec end;
		double start;
		double stop;
		char buffer[1000];
		uint32_t len = htobe32(i);
		char *write_ptr = buffer;
		memcpy(write_ptr, &len, sizeof(len));
		write_ptr += sizeof(len);
		memset(write_ptr, 'b', i);
		write_ptr[i] = '\0';

		clock_gettime(CLOCK_MONOTONIC, &begin);
		start = ((begin.tv_sec * 1000000.0) + (begin.tv_nsec / 1000.0)) / (double)ROUNDS;

		unsigned int round;
		for (round = 0; round < ROUNDS; round++) {
			write(fd, buffer, sizeof(len) + i);

			uint32_t msg_len;
			ssize_t got = read(fd, &msg_len, sizeof(msg_len));
			if (got != sizeof(msg_len)) {
				fprintf(stderr, "could not read enough for msg_len: %zd\n", got);
				return EXIT_FAILURE;
			}
			msg_len = be32toh(msg_len);
			if (msg_len != be32toh(len)) {
				fprintf(stderr, "msglen != len\n");
			}

			char read_buffer[1000];
			got = read(fd, read_buffer, msg_len);
			if (got != msg_len) {
				fprintf(stderr, "could not read enough of message!\n");
			}
			read_buffer[msg_len] = '\0';
			if (strcmp(read_buffer, &buffer[sizeof(len)]) != 0) {
				fprintf(stderr, "received message not the same like send!\n");
			}
		}
		clock_gettime(CLOCK_MONOTONIC, &end);
		stop = ((end.tv_sec * 1000000.0) + (end.tv_nsec / 1000.0)) / (double)ROUNDS;
		fprintf(stdout, "%u %f\n", i, stop - start);
		fflush(stdout);
	}

	close(fd);
	return EXIT_SUCCESS;
}
