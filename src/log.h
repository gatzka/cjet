#ifndef CJET_LOG_H
#define CJET_LOG_H

#ifdef TESTING

#ifdef __cplusplus
extern "C" {
#endif

void test_log(const char *format, ...);
char *get_log_buffer(void);

#ifdef __cplusplus
}
#endif

#define log_err(...) test_log(__VA_ARGS__)
#define log_warn(...) test_log(__VA_ARGS__)
#define log_info(...) test_log(__VA_ARGS__)

#else

#include <syslog.h>
#define log_err(...) syslog(LOG_ERR, __VA_ARGS__)
#define log_warn(...) syslog(LOG_WARNING, __VA_ARGS__)
#define log_info(...) syslog(LOG_INFO, __VA_ARGS__)

#endif

#endif
