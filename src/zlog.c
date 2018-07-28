#include "zlog.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#ifdef __WIN32
#define CL_RESET ""
#define CL_NORMAL CL_RESET
#define CL_NONE  CL_RESET
#define CL_WHITE ""
#define CL_GRAY  ""
#define CL_RED  ""
#define CL_GREEN ""
#define CL_YELLOW ""
#define CL_BLUE  ""
#define CL_MAGENTA ""
#define CL_CYAN  ""
#else
#define CL_RESET "\033[0;0m"
#define CL_NORMAL CL_RESET
#define CL_NONE  CL_RESET
#define CL_WHITE "\033[1;29m"
#define CL_GRAY  "\033[1;30m"
#define CL_RED  "\033[1;31m"
#define CL_GREEN "\033[1;32m"
#define CL_YELLOW "\033[1;33m"
#define CL_BLUE  "\033[1;34m"
#define CL_MAGENTA "\033[1;35m"
#define CL_CYAN  "\033[1;36m"
#endif

static int limit = ZLOG_INFO;

static zlog_before_log_func_t before_log_cb;
static zlog_after_log_func_t after_log_cb;

int zlog_set_level(int level)
{
	int previous = limit;
	limit = level;
	return previous;
}

zlog_before_log_func_t
zlog_set_before_log_cb(zlog_before_log_func_t cb)
{
	zlog_before_log_func_t last = before_log_cb;
	before_log_cb = cb;
	return  last;
}

zlog_after_log_func_t
zlog_set_after_log_cb(zlog_after_log_func_t cb)
{
	zlog_after_log_func_t last = after_log_cb;
	after_log_cb = cb;
	return last;
}

static int __zlog_message(int level, const char *format, va_list ap)
{
	char prefix[40];

	switch (level) {
	case ZLOG_NONE: // None
		strcpy(prefix, "");
		break;
	case ZLOG_DEBUG: // Bright Cyan, important stuff!
		strcpy(prefix, CL_CYAN"[Debug]"CL_RESET": ");
		break;
	case ZLOG_INFO: // Bright White (Variable information)
		strcpy(prefix, CL_WHITE"[Info]"CL_RESET": ");
		break;
	case ZLOG_NOTICE: // Bright White (Less than a warning)
		strcpy(prefix, CL_WHITE"[Notice]"CL_RESET": ");
		break;
	case ZLOG_WARN: // Bright Yellow
		strcpy(prefix, CL_YELLOW"[Warning]"CL_RESET": ");
		break;
	case ZLOG_ERROR: // Bright Red (Regular errors)
		strcpy(prefix, CL_RED"[Error]"CL_RESET": ");
		break;
	case ZLOG_FATAL: // Bright Red (Fatal errors, abort(); if possible)
		strcpy(prefix, CL_RED"[Fatal Error]"CL_RESET": ");
		break;
	default:
		printf("__zlog_message: Invalid level passed.\n");
		return 1;
	}

	printf("%s", prefix);
	vprintf(format, ap);
	fflush(stdout);

	return 0;
}

int zlog_message(int level, const char *format, ...)
{
	int rc;
	va_list ap;

	assert(format && *format != '\0');

	if (level < limit && level != ZLOG_NONE) return 0;

	va_start(ap, format);
	if (before_log_cb) before_log_cb(level, format, ap);
	va_end(ap);

	va_start(ap, format);
	rc = __zlog_message(level, format, ap);
	va_end(ap);

	va_start(ap, format);
	if (after_log_cb) after_log_cb(level, format, ap);
	va_end(ap);

	return rc;
}
