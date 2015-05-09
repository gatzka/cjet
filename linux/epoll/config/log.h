#ifndef CJET_LOG_H
#define CJET_LOG_H

#include <syslog.h>

#define log_err(...) syslog(LOG_ERR, __VA_ARGS__)

#endif
