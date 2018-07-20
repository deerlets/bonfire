#include "qbuf.h"
#include <stdlib.h>
#include <string.h>

#define RAW_SIZE 4096

struct __queue_buf {
	char *rawbuf;
	size_t size;
	size_t offset_in;
	size_t offset_out;
};

qbuf_t *qbuf_new(size_t size)
{
	if (size == 0)
		size = RAW_SIZE;

	qbuf_t *self = (qbuf_t*)calloc(sizeof(qbuf_t), 1);
	if (!self) return NULL;

	self->rawbuf = (char*)calloc(size, 1);
	if (!self->rawbuf) {
		free(self);
		return NULL;
	}

	self->size = size;
	self->offset_in = 0;
	self->offset_out = 0;

	return self;
}

void qbuf_delete(qbuf_t *self)
{
	if (self) {
		free(self->rawbuf);
		free(self);
	}
}

int qbuf_realloc(qbuf_t *self, size_t len)
{
	void *newbuf = realloc(self->rawbuf, len);
	if (newbuf) {
		self->rawbuf = newbuf;
		self->size = len;
		return 0;
	} else {
		return -1;
	}
}

char *qbuf_rawbuf_out_pos(qbuf_t *self)
{
	return self->rawbuf + self->offset_out;
}

char *qbuf_rawbuf_in_pos(qbuf_t *self)
{
	return self->rawbuf + self->offset_in;
}

size_t qbuf_size(qbuf_t *self)
{
	return self->size;
}

size_t qbuf_garbage(qbuf_t *self)
{
	return self->offset_out;
}

size_t qbuf_used(qbuf_t *self)
{
	return self->offset_in - self->offset_out;
}

size_t qbuf_spare(qbuf_t *self)
{
	return self->size - self->offset_in;
}

size_t qbuf_collect(qbuf_t *self, int policy)
{
	int policy_do = 1;

	if (policy & QBUF_COLLECT_POLICY_LESS_SPARE) {
		if (qbuf_spare(self) > self->size>>2)
			policy_do = 0;
	}

	if (policy & QBUF_COLLECT_POLICY_LARGE_GARBAGE) {
		if (qbuf_garbage(self) < self->size>>2)
			policy_do = 0;
	}

	// condition 0: unsed == 0
	// condition 1: policy_do == 1
	if (!qbuf_used(self)) {
		self->offset_in = self->offset_out = 0;
	} else if (policy_do) {
		/* method 1
		self->offset_in -= self->offset_out;
		memmove(self->rawbuf, qbuf_rawbuf_out_pos(self), self->offset_in);
		self->offset_out = 0;
		*/
		memmove(self->rawbuf, qbuf_rawbuf_out_pos(self), qbuf_used(self));
		self->offset_in = qbuf_used(self);
		self->offset_out = 0;
	}

	return qbuf_spare(self);
}

size_t qbuf_offset_out_head(qbuf_t *self, size_t len)
{
	self->offset_out += len;

	if (self->offset_out > self->offset_in)
		self->offset_out = self->offset_in;

	return qbuf_used(self);
}

size_t qbuf_offset_in_head(qbuf_t *self, size_t len)
{
	self->offset_in += len;

	if (self->offset_in > self->size)
		self->offset_in = self->size;

	return qbuf_spare(self);
}

size_t qbuf_peek(qbuf_t *self, void *buf, size_t len)
{
	size_t len_can_out = len <= qbuf_used(self) ? len : qbuf_used(self);
	memcpy(buf, qbuf_rawbuf_out_pos(self), len_can_out);

	return len_can_out;
}

size_t qbuf_read(qbuf_t *self, void *buf, size_t len)
{
	int nread = qbuf_peek(self, buf, len);
	qbuf_offset_out_head(self, nread);

	return nread;
}

size_t qbuf_write(qbuf_t *self, const void *buf, size_t len)
{
	if (len > qbuf_spare(self))
		qbuf_collect(self, QBUF_COLLECT_POLICY_NONE);

	if (len > qbuf_spare(self))
		qbuf_realloc(self, self->size > len ? self->size<<1 : len<<1);

	size_t len_can_in = len <= qbuf_spare(self) ? len : qbuf_spare(self);
	memcpy(qbuf_rawbuf_in_pos(self), buf, len_can_in);
	qbuf_offset_in_head(self, len_can_in);

	return len_can_in;
}
