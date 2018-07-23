#ifndef __ZERO_ZLOG_H
#define __ZERO_ZLOG_H

#include "list.h"
#include <stdarg.h>

enum zlog_level {
	ZLOG_DEBUG,
	ZLOG_INFO,
	ZLOG_NOTICE,
	ZLOG_WARN,
	ZLOG_ERROR,
	ZLOG_FATAL = 100,
	ZLOG_NONE,
};

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*zlog_before_log_func_t)(const char *string, va_list ap);
typedef void (*zlog_after_log_func_t)(const char *string, va_list ap);

int zlog_set_level(int level);
zlog_before_log_func_t zlog_set_before_log_cb(zlog_before_log_func_t cb);
zlog_after_log_func_t zlog_set_after_log_cb(zlog_after_log_func_t cb);

int zlog_debug(const char *, ...);
int zlog_info(const char *, ...);
int zlog_notice(const char *, ...);
int zlog_warn(const char *, ...);
int zlog_error(const char *, ...);
int zlog_fatal(const char *, ...);
int zlog_none(const char *, ...);

#define LOG_DEBUG zlog_debug
#define LOG_INFO zlog_info
#define LOG_NOTICE zlog_notice
#define LOG_WARN zlog_warn
#define LOG_ERROR zlog_error
#define LOG_FATAL zlog_fatal
#define LOG_NONE zlog_none

#ifdef __cplusplus
}
#endif
#endif
