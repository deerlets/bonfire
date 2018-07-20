#ifndef __ZERO_QBUF_H
#define __ZERO_QBUF_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define QBUF_COLLECT_POLICY_NONE 0
#define QBUF_COLLECT_POLICY_LESS_SPARE 1
#define QBUF_COLLECT_POLICY_LARGE_GARBAGE 2

typedef struct __queue_buf qbuf_t;

qbuf_t *qbuf_new(size_t size);
void qbuf_delete(qbuf_t *self);
int qbuf_realloc(qbuf_t *self, size_t len);

char *qbuf_rawbuf_out_pos(qbuf_t *self);
char *qbuf_rawbuf_in_pos(qbuf_t *self);
size_t qbuf_size(qbuf_t *self);
size_t qbuf_garbage(qbuf_t *self);
size_t qbuf_used(qbuf_t *self);
size_t qbuf_spare(qbuf_t *self);
size_t qbuf_collect(qbuf_t *self, int policy);
size_t qbuf_offset_out_head(qbuf_t *self, size_t len);
size_t qbuf_offset_in_head(qbuf_t *self, size_t len);

size_t qbuf_peek(qbuf_t *self, void *buf, size_t len);
size_t qbuf_read(qbuf_t *self, void *buf, size_t len);
size_t qbuf_write(qbuf_t *self, const void *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif
