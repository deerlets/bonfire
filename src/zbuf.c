#include "zbuf.h"
#include <string.h>
#include <stdlib.h>

struct __zbuf {
	void *data;
	size_t size;
};

#define inner_of(ptr, type) ((type *)ptr->_)
#define inner_zbuf(ptr) inner_of(ptr, struct __zbuf)

int zbuf_init(zbuf_t *zbuf)
{
	inner_zbuf(zbuf)->size = 0;
	inner_zbuf(zbuf)->data = 0;
	return 0;
}

int zbuf_init_size(zbuf_t *zbuf, size_t size)
{
	if (size == 0)
		return zbuf_init(zbuf);

	inner_zbuf(zbuf)->size = size;
	inner_zbuf(zbuf)->data = malloc(size);

	if (inner_zbuf(zbuf)->data == NULL)
		return -1;

	return 0;
}

int zbuf_init_data(zbuf_t *zbuf, const void *data, size_t size)
{
	if (data == NULL || size == 0)
		return zbuf_init(zbuf);

	inner_zbuf(zbuf)->size = size;
	inner_zbuf(zbuf)->data = malloc(size);

	if (inner_zbuf(zbuf)->data == NULL)
		return -1;

	memcpy(inner_zbuf(zbuf)->data, data, size);
	return 0;
}

void zbuf_close(zbuf_t *zbuf)
{
	if (inner_zbuf(zbuf)->data)
		free(inner_zbuf(zbuf)->data);
	inner_zbuf(zbuf)->size = 0;
	inner_zbuf(zbuf)->data = NULL;
}

int zbuf_assign_data(zbuf_t *zbuf, const void *data, size_t size)
{
	zbuf_close(zbuf);
	return zbuf_init_data(zbuf, data, size);
}

size_t zbuf_size(zbuf_t *zbuf)
{
	return inner_zbuf(zbuf)->size;
}

void *zbuf_data(zbuf_t *zbuf)
{
	return inner_zbuf(zbuf)->data;
}
