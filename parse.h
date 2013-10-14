#ifndef CJET_PARSE_H
#define CJET_PARSE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int parse_message(char *msg, uint32_t length);

#ifdef __cplusplus
}
#endif

#endif
