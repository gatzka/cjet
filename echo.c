#include <stdint.h>

#include "io_ops.h"
#include "parse.h"
#include "peer.h"

int parse_message(char *msg, uint32_t length, struct peer *p)
{
	return send_message(p, msg, length);
}
