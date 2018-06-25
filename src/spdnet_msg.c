#include "spdnet.h"
#include <assert.h>
#include <string.h>
#include <zmq.h>

#define SPDNET_STRERROR_GEN(name, msg) case SPDNET_ ## name: return msg;
const char *spdnet_strerror(int err) {
	switch (err) {
		SPDNET_ERRNO_MAP(SPDNET_STRERROR_GEN)
	}
	return zmq_strerror(err);
}
#undef SPDNET_STRERROR_GEN

int spdnet_msg_init(struct spdnet_msg *msg)
{
	memset(msg, 0, sizeof(*msg));

	if (zmq_msg_init(&msg->__sockid) == -1)
		return -1;
	if (zmq_msg_init(&msg->__header) == -1)
		return -1;
	return zmq_msg_init(&msg->__content);
}

int spdnet_msg_init_data(struct spdnet_msg *msg,
                         const void *sockid, int id_size,
                         const void *header, int hdr_size,
                         const void *content, int cnt_size)
{
	memset(msg, 0, sizeof(*msg));

	if (id_size == -1)
		id_size = sockid ? strlen(sockid) : 0;
	if (hdr_size == -1)
		hdr_size = header ? strlen(header) : 0;
	if (cnt_size == -1)
		cnt_size = content ? strlen(content) : 0;

	// sockid
	if (id_size && sockid) {
		zmq_msg_init_size(&msg->__sockid, id_size);
		memcpy(zmq_msg_data(&msg->__sockid), sockid, id_size);
	} else
		zmq_msg_init(&msg->__sockid);

	// header
	if (hdr_size && header) {
		zmq_msg_init_size(&msg->__header, hdr_size);
		memcpy(zmq_msg_data(&msg->__header), header, hdr_size);
	} else
		zmq_msg_init(&msg->__header);

	// content
	if (cnt_size && content) {
		zmq_msg_init_size(&msg->__content, cnt_size);
		memcpy(zmq_msg_data(&msg->__content), content, cnt_size);
	} else
		zmq_msg_init(&msg->__content);

	return 0;
}

int spdnet_msg_close(struct spdnet_msg *msg)
{
	int rc = 0;

	rc = zmq_msg_close(&msg->__sockid);
	assert(rc == 0);
	rc = zmq_msg_close(&msg->__header);
	assert(rc == 0);
	rc = zmq_msg_close(&msg->__content);
	assert(rc == 0);
	return 0;
}

int spdnet_msg_move(struct spdnet_msg *dst, struct spdnet_msg *src)
{
	zmq_msg_move(&dst->__sockid, &src->__sockid);
	zmq_msg_move(&dst->__header, &src->__header);
	zmq_msg_move(&dst->__content, &src->__content);
	memmove(&dst->__meta, &src->__meta, sizeof(src->__meta));
	return 0;
}

int spdnet_msg_copy(struct spdnet_msg *dst, struct spdnet_msg *src)
{
	zmq_msg_copy(&dst->__sockid, &src->__sockid);
	zmq_msg_copy(&dst->__header, &src->__header);
	zmq_msg_copy(&dst->__content, &src->__content);
	memcpy(&dst->__meta, &src->__meta, sizeof(src->__meta));
	return 0;
}

zmq_msg_t *spdnet_msg_get(struct spdnet_msg *msg, const char *name)
{
	if (!strcmp(name, "sockid"))
		return &msg->__sockid;
	else if (!strcmp(name, "header"))
		return &msg->__header;
	else if (!strcmp(name, "content"))
		return &msg->__content;
	else
		return NULL;
}

const char *spdnet_msg_gets(struct spdnet_msg *msg, const char *property)
{
	if (!strcmp(property, "name"))
		return msg->__meta.name;
	return NULL;
}

int spdnet_msg_sets(struct spdnet_msg *msg, const char *property,
                    const char *value)
{
	if (!strcmp(property, "name"))
		snprintf(msg->__meta.name, SPDNET_NAME_SIZE, "%s", value);
	else
		return -1;

	return 0;
}
