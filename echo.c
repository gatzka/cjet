#include <stdint.h>

#include "compiler.h"
#include "parse.h"
#include "peer.h"

int parse_message(const char *msg, uint32_t length, struct peer *p)
{
	return send_message(p, msg, length);
}
