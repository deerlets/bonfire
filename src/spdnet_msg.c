#include "spdnet.h"
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <zmq.h>

#define SPDNET_STRERROR_GEN(name, msg) case SPDNET_ ## name: return msg;
const char *spdnet_strerror(int err) {
	switch (err) {
		SPDNET_ERRNO_MAP(SPDNET_STRERROR_GEN)
	}
	return zmq_strerror(err);
}
#undef SPDNET_STRERROR_GEN

int spdnet_meta_serialize(spdnet_meta_t *meta, void *buf, size_t len)
{
	int rc;
	assert(len >= sizeof(*meta) + strlen(meta->name) + 1);

	memcpy(buf, meta, sizeof(*meta));
	rc = sizeof(*meta);
	rc += sprintf(buf + rc, "%s", meta->name);
	rc++;

	return rc;
}

int spdnet_meta_unserialize(spdnet_meta_t *meta, void *buf, size_t len)
{
	char *cur;
	assert(*((char *)buf + len - 1) == '\0');

	// must free meta->name before memcpy
	if (meta->name) free(meta->name);
	memcpy(meta, buf, sizeof(*meta));

	cur = buf + sizeof(*meta);
	meta->name = malloc(strlen(cur) + 1);
	strcpy(meta->name, cur);

	return 0;
}

int spdnet_msg_init(struct spdnet_msg *msg)
{
	memset(msg, 0, sizeof(*msg));

	if (zmq_msg_init(&msg->__sockid) == -1)
		return -1;
	if (zmq_msg_init(&msg->__header) == -1)
		return -1;
	if (zmq_msg_init(&msg->__content) == -1)
		return -1;

	return 0;
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
		zmq_msg_init_size(MSG_SOCKID(msg), id_size);
		memcpy(MSG_SOCKID_DATA(msg), sockid, id_size);
	} else
		zmq_msg_init(MSG_SOCKID(msg));

	// header
	if (hdr_size && header) {
		zmq_msg_init_size(MSG_HEADER(msg), hdr_size);
		memcpy(MSG_HEADER_DATA(msg), header, hdr_size);
	} else
		zmq_msg_init(MSG_HEADER(msg));

	// content
	if (cnt_size && content) {
		zmq_msg_init_size(MSG_CONTENT(msg), cnt_size);
		memcpy(MSG_CONTENT_DATA(msg), content, cnt_size);
	} else
		zmq_msg_init(MSG_CONTENT(msg));

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
	if (msg->__meta.name) {
		free(msg->__meta.name);
		msg->__meta.name = NULL;
	}
	return 0;
}

int spdnet_msg_move(struct spdnet_msg *dst, struct spdnet_msg *src)
{
	zmq_msg_move(&dst->__sockid, &src->__sockid);
	zmq_msg_move(&dst->__header, &src->__header);
	zmq_msg_move(&dst->__content, &src->__content);
	memmove(&dst->__meta, &src->__meta, sizeof(src->__meta));
	src->__meta.name = NULL;
	return 0;
}

int spdnet_msg_copy(struct spdnet_msg *dst, struct spdnet_msg *src)
{
	zmq_msg_init_size(MSG_SOCKID(dst), MSG_SOCKID_SIZE(src));
	memcpy(MSG_SOCKID_DATA(dst), MSG_SOCKID_DATA(src), MSG_SOCKID_SIZE(src));

	zmq_msg_init_size(MSG_HEADER(dst), MSG_HEADER_SIZE(src));
	memcpy(MSG_HEADER_DATA(dst), MSG_HEADER_DATA(src), MSG_HEADER_SIZE(src));

	zmq_msg_init_size(MSG_CONTENT(dst), MSG_CONTENT_SIZE(src));
	memcpy(MSG_CONTENT_DATA(dst), MSG_CONTENT_DATA(src),
	       MSG_CONTENT_SIZE(src));

	memcpy(&dst->__meta, &src->__meta, sizeof(src->__meta));
	dst->__meta.name = malloc(strlen(src->__meta.name) + 1);
	strcpy(dst->__meta.name, src->__meta.name);
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
