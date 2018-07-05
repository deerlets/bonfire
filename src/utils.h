#ifndef __ZERO_UTILS_H
#define __ZERO_UTILS_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

const char *get_ifaddr();
void bytes_to_hexstr(uint8_t *bytes, int len, char *hexstr);
void hexstr_to_bytes(const char *hexstr, uint8_t *bytes, size_t size);

#ifdef __cplusplus
}
#endif
#endif
