#ifndef __ZERO_ZBUF_H
#define __ZERO_ZBUF_H

#include <stddef.h> // size_t

#ifdef __cplusplus
extern "C" {
#endif

typedef struct zbuf_t {
	char _[32];
} zbuf_t;

int zbuf_init(zbuf_t *zbuf);
int zbuf_init_size(zbuf_t *zbuf, size_t size);
int zbuf_init_data(zbuf_t *zbuf, const void *data, size_t size);
void zbuf_close(zbuf_t *zbuf);
int zbuf_assign_data(zbuf_t *zbuf, const void *data, size_t size);
size_t zbuf_size(zbuf_t *zbuf);
void *zbuf_data(zbuf_t *zbuf);

#ifdef __cplusplus
}
#endif
#endif
