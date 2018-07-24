#ifndef __ZERO_ZLOG_H
#define __ZERO_ZLOG_H

#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

enum zlog_level {
	ZLOG_DEBUG,
	ZLOG_INFO,
	ZLOG_NOTICE,
	ZLOG_WARN,
	ZLOG_ERROR,
	ZLOG_FATAL = 100,
	ZLOG_NONE,
};

int zlog_set_level(int level);

typedef void (*zlog_before_log_func_t)(const char *string, va_list ap);
typedef void (*zlog_after_log_func_t)(const char *string, va_list ap);

zlog_before_log_func_t zlog_set_before_log_cb(zlog_before_log_func_t cb);
zlog_after_log_func_t zlog_set_after_log_cb(zlog_after_log_func_t cb);

int zlog_message(int level, const char *format, ...);

#define LOG_DEBUG(format, ...) zlog_message(ZLOG_DEBUG, format, ##__VA_ARGS__)
#define LOG_INFO(format, ...) zlog_message(ZLOG_INFO, format, ##__VA_ARGS__)
#define LOG_NOTICE(format, ...) zlog_message(ZLOG_DEBUG, format, ##__VA_ARGS__)
#define LOG_WARN(format, ...) zlog_message(ZLOG_WARN, format, ##__VA_ARGS__)
#define LOG_ERROR(format, ...) zlog_message(ZLOG_ERROR, format, ##__VA_ARGS__)
#define LOG_FATAL(format, ...) zlog_message(ZLOG_FATAL, format, ##__VA_ARGS__)
#define LOG_NONE(format, ...) zlog_message(ZLOG_NONE, format, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif
#endif
