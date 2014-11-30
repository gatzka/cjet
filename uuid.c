#include "uuid.h"

static int uuid = 0;

int get_routed_request_uuid(void)
{
	return uuid++;
}
