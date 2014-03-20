#include <stdint.h>

#include "parse.h"
#include "peer.h"
#include "peer_io_ops.h"

int parse_message(char *msg, uint32_t length, struct peer *p)
{
	return send_message(p, msg, length);
}
