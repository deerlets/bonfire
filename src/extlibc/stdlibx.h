#ifndef __STDLIBX_H
#define __STDLIBX_H

#include <stddef.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

size_t random_gen(void *buf, size_t size);
char *uuid_v4_gen();

#ifdef __cplusplus
}
#endif
#endif
