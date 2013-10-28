#include <ctype.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "hash_func.h"

#define MAX_MESSAGES 100
#define MAX_LINE_LENGTH 1000

struct message {
	uint32_t hash;
	char *name;
};

static int get_messages(FILE *message_string_file, struct message *buffer, int max_msg)
{
	char line[MAX_LINE_LENGTH];
	int i = 0;
	int j;

	while ((fgets(line, sizeof(line), message_string_file)) != NULL) {
		size_t line_length = strlen(line);
		if (line[line_length - 1] == '\n') {
		    line[line_length] = '\0';
			line_length--;
		}
		if (i >= max_msg) {
			fprintf(stderr, "Too many messages in file, adjust MAX_MESSAGES!\n");
			goto too_many_messages;
		}
		if (strlen(line) > 0) {
			char *name = malloc(line_length + 1);
			if (name == NULL) {
				fprintf(stderr, "Could not allocate memory for message name!\n");
				goto malloc_failed;
			}
			strncpy(name, line, line_length);
			buffer[i].name = name;
			buffer[i].hash = hash_func_string(name);
			i++;
		}
	}
	return i;

too_many_messages:
malloc_failed:
	for (j = 0; j < i; j++) {
		free(buffer[j].name);
	}
	return -1;
}

static void free_message_names(struct message *buffer, int num_messages)
{
	int i;
	for (i = 0; i < num_messages; i++) {
		free(buffer[i].name);
	}

}

static int check_hashes(struct message *buffer, int num_messages)
{
	int i;
	int j;
	if (num_messages <= 1) {
		return 0;
	}

	for (i = 0; i < num_messages - 1; i++) {
		for (j = i + 1; j < num_messages; j++) {
			if (buffer[i].hash == buffer[j].hash) {
				fprintf(stderr, "Hashes for \"%s\" (%u) and \"%s\" (%u) are identical!\n",
				        buffer[i].name, buffer[i].hash, buffer[j].name, buffer[j].hash);
				return -1;
			}
		}
	}
	return 0;
}

static void generate_hash_file(FILE *hash_algo_file, struct message *buffer, int num_messages)
{
	int i;
	size_t nread;
	char buf[1000];

	fprintf(stdout, "#ifndef MESSAGE_HASH\n");
	fprintf(stdout, "#define MESSAGE_HASH\n\n");

	for (i = 0; i < num_messages; i++) {
		unsigned int j;
		fprintf(stdout, "#define ");
		for (j = 0; j < strlen(buffer[i].name); j++) {
			fprintf(stdout, "%c", toupper(buffer[i].name[j]));
		}
		fprintf(stdout, "_MESSAGE_HASH %u\n", buffer[i].hash);
	}
	fprintf(stdout, "\n#include <stdint.h>\n\n");

	while ((nread = fread(buf, 1, sizeof buf, hash_algo_file)) > 0)
		fwrite(buf, 1, nread, stdout);

	fprintf(stdout, "\n#endif\n");
}

int main(int argc, char *argv[])
{
	FILE *message_string_file;
	FILE *hash_algo_file;
	int num_messages;
	int hashes_unique;
	struct message *buffer;

	if (argc != 3) {
		fprintf(stderr, "Usage: %s <file with message strings> <file with C hash function>\n", argv[0]);
		return EXIT_FAILURE;
	}

	message_string_file = fopen(argv[1], "r");
	if (message_string_file == NULL) {
		fprintf(stderr, "Cannot open message string file %s\n", argv[1]);
		return EXIT_FAILURE;
	}

	buffer = malloc(MAX_MESSAGES * sizeof(*buffer));
	if (buffer == NULL) {
		fprintf(stderr, "Could not allocate memory for message buffer!\n");
		goto malloc_failed;
	}
	num_messages = get_messages(message_string_file, buffer, MAX_MESSAGES);
	if (num_messages == -1) {
		fprintf(stderr, "Error reading messages\n");
		goto msg_read_failed;
	}

	hashes_unique = check_hashes(buffer, num_messages);
	if (hashes_unique == -1) {
		goto hashes_not_unique;
	}

	hash_algo_file = fopen(argv[2], "r");
	if (hash_algo_file == NULL) {
		fprintf(stderr, "Cannot open hash file %s\n", argv[2]);
		goto hash_algo_file_failed;
	}

	generate_hash_file(hash_algo_file, buffer, num_messages);

	fclose(hash_algo_file);
	free_message_names(buffer, num_messages);
	free(buffer);
	fclose(message_string_file);
	return EXIT_SUCCESS;

hash_algo_file_failed:
hashes_not_unique:
	free_message_names(buffer, num_messages);
msg_read_failed:
	free(buffer);
malloc_failed:
	fclose(message_string_file);
	return EXIT_FAILURE;

}
