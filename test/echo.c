#include <arpa/inet.h>
#include <endian.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main()
{
	struct sockaddr_in serv_addr;
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
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

	char buffer[1000];
	char *write_ptr = buffer;


	const char msg[] = "bla";

	uint32_t len = strlen(msg);
	len = htobe32(len);
	memcpy(write_ptr, &len, sizeof(len));
	write_ptr += sizeof(len);
	memcpy(write_ptr, msg, strlen(msg));

	int i;
	for (i = 0; i < 1000000; i++) {
		write(fd, buffer, sizeof(len) + strlen(msg));

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
		if (strcmp(read_buffer, msg) != 0) {
			fprintf(stderr, "received message not the same like send!\n");
		}
	}

	close(fd);
	return EXIT_SUCCESS;
}
