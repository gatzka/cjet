#ifndef CJET_ERROR_CODES_H
#define CJET_ERROR_CODES_H

#include <errno.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef EWOULDBLOCK
#define EWOULDBLOCK 9901
#endif

#ifndef EAGAIN
#define EAGAIN 9902
#endif

enum cjet_system_error {
	operation_would_block = EWOULDBLOCK,
	resource_unavailable_try_again = EAGAIN
};

#ifdef __cplusplus
}
#endif

#endif
