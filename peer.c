#include <arpa/inet.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "compiler.h"
#include "config.h"
#include "list.h"
#include "parse.h"
#include "peer.h"
#include "state.h"

#define ROUND_UP(n,d) ((((n) + (d) - 1) / (d)) * (d))

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
	p->write_buffer = NULL;
	p->write_buffer_size = 0;
	p->to_write = 0;
	return p;
}

void free_peer(struct peer *p)
{
	remove_all_states_from_peer(p);
	free(p->write_buffer);
	free(p);
}

static ptrdiff_t unread_space(const struct peer *p)
{
	return &(p->read_buffer[MAX_MESSAGE_SIZE]) - p->read_ptr;
}

static ptrdiff_t free_space(const struct peer *p)
{
	return &(p->read_buffer[MAX_MESSAGE_SIZE]) - p->write_ptr;
}

static void reorganize_read_buffer(struct peer *p)
{
	ptrdiff_t unread = p->write_ptr - p->read_ptr;
	if (unread != 0) {
		memmove(p->read_buffer, p->read_ptr, (size_t)unread);
		p->write_ptr = p->read_buffer + unread;
	} else {
		p->write_ptr = p->read_buffer;
	}
	p->read_ptr = p->read_buffer;
}

char *get_read_ptr(struct peer *p, unsigned int count)
{
	if (unlikely(count > unread_space(p))) {
		fprintf(stderr, "peer asked for too much data: %d!\n", count);
		return NULL;
	}
	while (1) {
		ssize_t read_length;
		if (p->write_ptr - p->read_ptr >= count) {
			char *read_ptr = p->read_ptr;
			p->read_ptr += count;
			return read_ptr;
		}

		read_length = READ(p->fd, p->write_ptr, (size_t)free_space(p));
		if (unlikely(read_length == 0)) {
			/* peer closed connection */
			return NULL;
		}
		if (read_length == -1) {
			if ((errno != EAGAIN) &&
			    (errno != EWOULDBLOCK)) {
				fprintf(stderr, "unexpected read error: %s!\n", strerror(errno));
				return NULL;
			}
			return (char *)-1;
		}
		p->write_ptr += read_length;
	}
}

static int allocate_new_write_buffer(struct peer *p, size_t bytes_to_copy)
{
	char *new_write_buffer;

	size_t new_buffer_size = ROUND_UP((p->write_buffer_size + bytes_to_copy), WRITE_BUFFER_CHUNK);
	if (unlikely(new_buffer_size > MAX_WRITE_BUFFER_SIZE)) {
		return -1;
	}
	new_write_buffer = realloc(p->write_buffer, new_buffer_size);
	if (new_write_buffer == NULL) {
		fprintf(stderr, "Allocation for write buffer failed!\n");
		goto realloc_failed;
	}
	p->write_buffer = new_write_buffer;
	p->write_buffer_size = new_buffer_size;
	return 0;

realloc_failed:
	return -1;
}

int copy_msg_to_write_buffer(struct peer *p, const void *rendered, uint32_t msg_len_be, size_t already_written)
{
	const char *message_ptr;
	size_t msg_offset;
	size_t to_write;
	char *write_buffer_ptr;
	uint32_t msg_len = ntohl(msg_len_be);
	size_t free_space_in_buf = p->write_buffer_size - p->to_write;
	size_t bytes_to_copy = msg_len + sizeof(msg_len_be) - already_written;

	if (bytes_to_copy > free_space_in_buf) {
		if (allocate_new_write_buffer(p, bytes_to_copy) == -1) {
			goto alloc_failed;
		}
	}

	write_buffer_ptr = p->write_buffer + p->to_write;
	if (already_written < sizeof(msg_len_be)) {
		char *msg_len_ptr = (char*)(&msg_len_be);
		msg_len_ptr += already_written;
		to_write = sizeof(msg_len_be) - already_written;
		memcpy(write_buffer_ptr, msg_len_ptr, to_write);
		write_buffer_ptr += to_write;
		already_written += to_write;
		p->to_write += to_write;
	}

	msg_offset = already_written - sizeof(msg_len_be);
	message_ptr = (char *)rendered + msg_offset;
	to_write = msg_len - msg_offset;
	memcpy(write_buffer_ptr, message_ptr, to_write);
	p->to_write += to_write;

	return 0;

alloc_failed:
	return -1;
}

int send_buffer(struct peer *p)
{
	char *write_buffer_ptr = p->write_buffer;
	while (p->to_write != 0) {
		ssize_t written;
		written = SEND(p->fd, write_buffer_ptr, p->to_write, MSG_NOSIGNAL);
		if (unlikely(written == -1)) {
			if (unlikely((errno != EAGAIN) &&
			             (errno != EWOULDBLOCK))) {
				return -1;
			}
			memmove(p->write_buffer, write_buffer_ptr, p->to_write);
			if (p->op != WRITE_MSG) {
				p->next_read_op = p->op;
				p->op = WRITE_MSG;
			}
			return -2;
		}
		write_buffer_ptr += written;
		p->to_write -= written;
	}
	return 0;
}

int send_message(struct peer *p, char *rendered, uint32_t len)
{
	int ret;
	ssize_t sent;
	size_t written = 0;
	uint32_t message_length = htonl(len);

	if (unlikely(p->op == WRITE_MSG)) {
		/* 
		 * There is already something in p->write_buffer, that hasn't
		 * been written yet because the socket had blocked. In this case
		 * just append the new message to p->write_buffer.
		 */
		 ret = copy_msg_to_write_buffer(p, rendered, message_length, 0);
		 return ret;
	}

	sent = SEND(p->fd, &message_length, sizeof(message_length), MSG_NOSIGNAL | MSG_MORE);
	if (likely(sent == sizeof(message_length))) {
		written = (size_t)sent;
		sent = SEND(p->fd, rendered, len, MSG_NOSIGNAL);
		if (likely(sent == len)) {
			return 0;
		}
	}
	if (sent > 0) {
		written += (size_t)sent;
	}

	if (unlikely((sent == -1) &&
	             ((errno != EAGAIN) &&
	              (errno != EWOULDBLOCK)))) {
		fprintf(stderr, "unexpected write error: %s!\n", strerror(errno));
		return -1;
	}
	if (unlikely(copy_msg_to_write_buffer(p, rendered, message_length, written) == -1)) {
		return -1;
	}

	if (sent == -1) {
		/* one of the write calls had blocked */
		p->next_read_op = p->op;
		p->op = WRITE_MSG;
		return 0;
	}

	/* 
	 * The write calls didn't block, but only wrote parts of the
	 * messages. Try to send the rest.
	 */
	ret = send_buffer(p);
	/*
	 * write in send_buffer blocked. This is not an error, so
	 * change ret to 0 (no error). Writing the missing stuff is
	 * handled via epoll / handle_all_peer_operations.
	 */
	if (ret == -2) {
		ret = 0;
	}
	return ret;
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
			ret = send_buffer(p);
			if (unlikely(ret == -1)) {
				return -1;
			}
			if (likely(ret == 0)) {
				p->op = p->next_read_op;
			}
			/*
			 * ret == -2 shows that send_buffer blocked. Leave
			 * everything like it is.
			 */
		}
			break;

		default:
			fprintf(stderr, "Unknown client operation!\n");
			return -1;
		}
	}
}
