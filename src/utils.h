#ifndef __ZERO_UTILS_H
#define __ZERO_UTILS_H

#include <stdint.h>
#include <stddef.h>
#include <sys/time.h>

#ifdef __cplusplus
extern "C" {
#endif

const char *get_ifaddr();
void bytes_to_hexstr(uint8_t *bytes, int len, char *hexstr);
void hexstr_to_bytes(const char *hexstr, uint8_t *bytes, size_t size);

static inline double timeval_to_double(struct timeval *tv)
{
	return tv->tv_sec + tv->tv_usec / 1000000.0;
}

static inline void double_to_timeval(double d, struct timeval *tv)
{
	tv->tv_sec = d;
	tv->tv_usec = (d - tv->tv_sec) * 1000000;
}

#ifdef __cplusplus
}
#endif
#endif
