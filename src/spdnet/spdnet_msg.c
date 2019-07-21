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

int spdnet_frame_init(spdnet_frame_t *frame)
{
	return zmq_msg_init(frame);
}
int spdnet_frame_init_size(spdnet_frame_t *frame, size_t size)
{
	return zmq_msg_init_size(frame, size);
}

int spdnet_frame_close(spdnet_frame_t *frame)
{
	return zmq_msg_close(frame);
}

int spdnet_frame_move(spdnet_frame_t *dst, spdnet_frame_t *src)
{
	return zmq_msg_move(dst, src);
}

int spdnet_frame_copy(spdnet_frame_t *dst, spdnet_frame_t *src)
{
	return zmq_msg_copy(dst, src);
}

void *spdnet_frame_data(spdnet_frame_t *frame)
{
	return zmq_msg_data(frame);
}

size_t spdnet_frame_size(const spdnet_frame_t *frame)
{
	return zmq_msg_size(frame);
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
	msg->__meta = NULL;

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

	// meta
	msg->__meta = NULL;

	return 0;
}

int spdnet_msg_close(struct spdnet_msg *msg)
{
	assert(zmq_msg_close(&msg->__sockid) == 0);
	assert(zmq_msg_close(&msg->__header) == 0);
	assert(zmq_msg_close(&msg->__content) == 0);

	if (msg->__meta) {
		free(msg->__meta);
		msg->__meta = NULL;
	}

	return 0;
}

int spdnet_msg_move(struct spdnet_msg *dst, struct spdnet_msg *src)
{
	zmq_msg_move(&dst->__sockid, &src->__sockid);
	zmq_msg_move(&dst->__header, &src->__header);
	zmq_msg_move(&dst->__content, &src->__content);

	assert(dst->__meta == NULL);
	if (src->__meta) {
		dst->__meta = src->__meta;
		src->__meta = NULL;
	}

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

	if (src->__meta) {
		memcpy(dst->__meta, src->__meta, sizeof(*dst->__meta));
	}

	return 0;
}

zmq_msg_t *spdnet_msg_get(struct spdnet_msg *msg, const char *frame_name)
{
	if (!strcmp(frame_name, "sockid"))
		return &msg->__sockid;
	else if (!strcmp(frame_name, "header"))
		return &msg->__header;
	else if (!strcmp(frame_name, "content"))
		return &msg->__content;
	return NULL;
}
