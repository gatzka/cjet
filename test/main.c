#include <arpa/inet.h>
#include <netinet/in.h>
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
	serv_addr.sin_port = htons(7899);

	int fd = socket(AF_INET, SOCK_STREAM, 0);

	if (connect(fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
		fprintf(stderr, "Failed to connect with server\n");
		return EXIT_FAILURE;
	}

	char buffer[1000];
	char *write_ptr = buffer;

	const char *msg = "Hello World!";
	uint32_t len = strlen(msg);
	len = htobe32(len);
	memcpy(write_ptr, &len, sizeof(len));
	write_ptr += sizeof(len);
	memcpy(write_ptr, msg, strlen(msg));
	write_ptr += strlen(msg);
	memcpy(write_ptr, &len, sizeof(len));
	write_ptr += sizeof(len);
	memcpy(write_ptr, msg, strlen(msg));
	write_ptr += strlen(msg);

	write(fd, buffer, write_ptr - buffer);
	close(fd);
	return EXIT_SUCCESS;
}
