#include <arpa/inet.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include "compiler.h"
#include "config.h"
#include "list.h"
#include "parse.h"
#include "peer.h"
#include "state.h"

struct peer *alloc_peer(int fd)
{
	struct peer *p;
	p = malloc(sizeof(*p));
	if (unlikely(p == NULL)) {
		return NULL;
	}
	INIT_LIST_HEAD(&p->state_list);
	p->fd = fd;
	p->op = READ_MSG_LENGTH;
	p->read_ptr = p->read_buffer;
	p->write_ptr = p->read_buffer;
	return p;
}

void free_peer(struct peer *p)
{
	remove_all_states_from_peer(p);
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

int copy_msg_to_write_buffer(struct peer *p, const void *rendered, uint32_t msg_len_be, size_t already_written)
{
	const char *message_ptr;
	int msg_offset;
	int to_write;
	int len;

	p->write_buffer_ptr = p->write_buffer;
	if (already_written < sizeof(msg_len_be)) {
		char *msg_len_ptr = (char*)(&msg_len_be);
		msg_len_ptr += already_written;
		to_write = sizeof(msg_len_be) - already_written;
		if (unlikely(to_write > MAX_MESSAGE_SIZE)) {
			goto no_space;
		}
		memcpy(p->write_buffer_ptr, msg_len_ptr, to_write);
		p->write_buffer_ptr += to_write;
		already_written += to_write;
	}

	msg_offset = already_written - sizeof(msg_len_be);
	message_ptr = (char *)rendered + msg_offset;
	len = ntohl(msg_len_be);
	to_write = len - msg_offset;
	if (unlikely(to_write > (MAX_MESSAGE_SIZE - (p->write_buffer_ptr - p->write_buffer)))) {
		goto no_space;
	}
	memcpy(p->write_buffer_ptr, message_ptr, to_write);
	p->write_buffer_ptr += to_write;
	p->to_write = p->write_buffer_ptr - p->write_buffer;
	p->write_buffer_ptr = p->write_buffer;

	return 0;

no_space:
	fprintf(stderr, "write buffer too small!\n");
	return -1;
}

int send_buffer(struct peer *p)
{
	while (p->to_write != 0) {
		int written;
		/* written = WRITE(p->fd, p->write_buffer_ptr, p->to_write); */
		written = send(p->fd, p->write_buffer_ptr, p->to_write, 0);
		if (unlikely(written == -1)) {
			if (unlikely((errno != EAGAIN) &&
			             (errno != EWOULDBLOCK))) {
				return -1;
			}
			p->next_read_op = p->op;
			p->op = WRITE_MSG;
			return -2;
		}
		p->write_buffer_ptr += written;
		p->to_write -= written;
	}
	return 0;
}

int send_message(struct peer *p, char *rendered, size_t len)
{
	struct iovec iov[2];
	int iovcnt;
	int written;

	uint32_t message_length = htonl(len);
	iov[0].iov_base = &message_length;
	iov[0].iov_len = sizeof(message_length);
	iov[1].iov_base = rendered;
	iov[1].iov_len = len;
	iovcnt = sizeof(iov) / sizeof(struct iovec);

	written = WRITEV(p->fd, iov, iovcnt);
	if (unlikely(written == -1)) {
		int ret;
		if ((errno != EAGAIN) &&
		    (errno != EWOULDBLOCK)) {
			fprintf(stderr, "unexpected write error: %d!\n", errno);
			return -1;
		}
		ret = copy_msg_to_write_buffer(p, rendered, message_length, 0);
		if (likely(ret == 0)) {
			p->next_read_op = p->op;
			p->op = WRITE_MSG;
		}
		return ret;
	}
	if (unlikely((size_t)written < len)) {
		int ret = copy_msg_to_write_buffer(p, rendered, message_length, written);
		if (likely(ret == 0)) {
			ret = send_buffer(p);
			/*
			 * write in send_buffer blocked. This is not an error, so
			 * change ret to 0 (no error). Writing the missing stuff is
			 * handled via epoll / handle_all_peer_operations.
			 */
			if (ret == -2) {
				ret = 0;
			}
		}
		return ret;
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
			message_length = ntohl(message_length);
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
			p->op = READ_MSG_LENGTH;
			ret = parse_message(message_ptr, message_length, p);
			if (unlikely(ret == -1)) {
				return -1;
			}
			reorganize_read_buffer(p);
			break;

		case WRITE_MSG: {
			int ret = send_buffer(p);
			if (unlikely(ret == -1)) {
				return -1;
			}
			if (likely(ret == 0)) {
				p->op = p->next_read_op;
			}
		}
			break;

		default:
			fprintf(stderr, "Unknown client operation!\n");
			return -1;
			break;
		}
	}
}
