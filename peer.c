#include <endian.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

#include "compiler.h"
#include "parse.h"
#include "peer.h"

struct peer *alloc_peer(int fd)
{
	struct peer *p;
	p = malloc(sizeof(*p));
	if (unlikely(p == NULL)) {
		return NULL;
	}
	p->fd = fd;
	p->op = READ_MSG_LENGTH;
	p->read_ptr = p->read_buffer;
	p->write_ptr = p->read_buffer;
	return p;
}

void free_peer(struct peer *p)
{
	free(p);
}

static int unread_space(const struct peer *p)
{
	return &(p->read_buffer[MAX_MESSAGE_SIZE]) - p->read_ptr;
}

static int free_space(const struct peer *p)
{
	return &(p->read_buffer[MAX_MESSAGE_SIZE]) - p->write_ptr;
}

static void reorganize_read_buffer(struct peer *p)
{
	unsigned int unread = p->write_ptr - p->read_ptr;
	if (unread != 0) {
		memmove(p->read_buffer, p->read_ptr, unread);
		p->write_ptr = p->read_buffer + unread;
	} else {
		p->write_ptr = p->read_buffer;
	}
	p->read_ptr = p->read_buffer;
}

char *get_read_ptr(struct peer *p, int count)
{
	if (unlikely(count > unread_space(p))) {
		fprintf(stderr, "peer asked for too much data: %d!\n", count);
		return NULL;
	}
	while (1) {
		int read_length;
		if (p->write_ptr - p->read_ptr >= count) {
			char *read_ptr = p->read_ptr;
			p->read_ptr += count;
			return read_ptr;
		}

		read_length = READ(p->fd, p->write_ptr, free_space(p));
		if (unlikely(read_length == 0)) {
			fprintf(stdout, "peer closed connection!\n");
			return NULL;
		}
		if (read_length == -1) {
			if ((errno != EAGAIN) &&
			    (errno != EWOULDBLOCK)) {
				fprintf(stderr, "unexpected read error: %d!\n", errno);
				return NULL;
			}
			return (char *)-1;
		}
		p->write_ptr += read_length;
	}
}

static int copy_msg_to_write_buffer(struct peer *p, const char *rendered, uint32_t message_length, int already_written)
{
	return 0;
}

int send_message(struct peer *p, char *rendered, size_t len)
{
	struct iovec iov[2];
	int iovcnt;
	int written;

	uint32_t message_length = htobe32(len);
	iov[0].iov_base = &message_length;
	iov[0].iov_len = sizeof(message_length);
	iov[1].iov_base = rendered;
	iov[1].iov_len = len;
	iovcnt = sizeof(iov) / sizeof(struct iovec);

	written = writev(p->fd, iov, iovcnt);
	if (unlikely(written == -1)) {
		int ret;
		if ((errno != EAGAIN) &&
		    (errno != EWOULDBLOCK)) {
			fprintf(stdout, "unexpected write error: %d!\n", errno);
			return -1;
		}
		ret = copy_msg_to_write_buffer(p, rendered, message_length, 0);
		p->op = WRITE_MSG;
		return 0;
	}
	if (unlikely((size_t)written < len)) {
		int ret = copy_msg_to_write_buffer(p, rendered, message_length, written);
		/*  TODO: send_buffer(p); */
		fprintf(stdout, "Not everything written, implement this case!\n");
		return 0;
	}

	return 0;
}

int handle_all_peer_operations(struct peer *p)
{
	uint32_t message_length;
	char *message_ptr;

	while (1) {
		char *message_length_ptr;
		int ret;

		switch (p->op) {
		case READ_MSG_LENGTH:
			message_length_ptr = get_read_ptr(p, sizeof(message_length));
			if (unlikely(message_length_ptr == NULL)) {
				return -1;
			} else if (message_length_ptr == (char *)-1) {
				return 0;
			}
			memcpy(&message_length, message_length_ptr, sizeof(message_length));
			message_length = be32toh(message_length);
			p->op = READ_MSG;
			p->msg_length = message_length;
			/*
			 *  CAUTION! This fall through is by design! Typically, the
			 *  length of a messages and the message itself will go into
			 *  a single TCP packet. This fall through eliminates an
			 *  additional loop iteration.
			 */

		case READ_MSG:
			message_length = p->msg_length;
			message_ptr = get_read_ptr(p, message_length);
			if (unlikely(message_ptr == NULL)) {
				return -1;
			} else if (message_ptr == (char *)-1) {
				return 0;
			}
			ret = parse_message(message_ptr, message_length, p);
			if (unlikely(ret == -1)) {
				return -1;
			}
			p->op = READ_MSG_LENGTH;
			reorganize_read_buffer(p);
			break;
		/* TODO: implement WRITE_MSG */
		default:
			fprintf(stderr, "Unknown client operation!\n");
			return -1;
			break;
		}
	}
}
