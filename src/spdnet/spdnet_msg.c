#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <zmq.h>
#include "spdnet-inl.h"

#define SPDNET_STRERROR_GEN(name, msg) case SPDNET_ ## name: return msg;
const char *spdnet_strerror(int err) {
    switch (err) {
        SPDNET_ERRNO_MAP(SPDNET_STRERROR_GEN)
    default:
        return zmq_strerror(err);
    }
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

    if (zmq_msg_init(&msg->__srcid) == -1)
        return -1;
    if (zmq_msg_init(&msg->__dstid) == -1)
        return -1;
    if (zmq_msg_init(&msg->__header) == -1)
        return -1;
    if (zmq_msg_init(&msg->__content) == -1)
        return -1;
    if (zmq_msg_init(&msg->__meta) == -1)
        return -1;

    return 0;
}

int spdnet_msg_init_data(
    struct spdnet_msg *msg,
    const void *dstid, int id_size,
    const void *header, int hdr_size,
    const void *content, int cnt_size)
{
    memset(msg, 0, sizeof(*msg));

    if (id_size == -1)
        id_size = dstid ? strlen(dstid) : 0;
    if (hdr_size == -1)
        hdr_size = header ? strlen(header) : 0;
    if (cnt_size == -1)
        cnt_size = content ? strlen(content) : 0;

    // srcid
    zmq_msg_init(MSG_SRCID(msg));

    // dstid
    if (id_size && dstid) {
        zmq_msg_init_size(MSG_DSTID(msg), id_size);
        memcpy(MSG_DSTID_DATA(msg), dstid, id_size);
    } else
        zmq_msg_init(MSG_DSTID(msg));

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
    zmq_msg_init(MSG_META(msg));

    return 0;
}

int spdnet_msg_close(struct spdnet_msg *msg)
{
    assert(zmq_msg_close(&msg->__srcid) == 0);
    assert(zmq_msg_close(&msg->__dstid) == 0);
    assert(zmq_msg_close(&msg->__header) == 0);
    assert(zmq_msg_close(&msg->__content) == 0);
    assert(zmq_msg_close(&msg->__meta) == 0);
    return 0;
}

int spdnet_msg_move(struct spdnet_msg *dst, struct spdnet_msg *src)
{
    zmq_msg_move(&dst->__srcid, &src->__srcid);
    zmq_msg_move(&dst->__dstid, &src->__dstid);
    zmq_msg_move(&dst->__header, &src->__header);
    zmq_msg_move(&dst->__content, &src->__content);
    zmq_msg_move(&dst->__meta, &src->__meta);
    return 0;
}

int spdnet_msg_copy(struct spdnet_msg *dst, struct spdnet_msg *src)
{
    zmq_msg_init_size(MSG_SRCID(dst), MSG_SRCID_SIZE(src));
    memcpy(MSG_SRCID_DATA(dst), MSG_SRCID_DATA(src), MSG_SRCID_SIZE(src));

    zmq_msg_init_size(MSG_DSTID(dst), MSG_DSTID_SIZE(src));
    memcpy(MSG_DSTID_DATA(dst), MSG_DSTID_DATA(src), MSG_DSTID_SIZE(src));

    zmq_msg_init_size(MSG_HEADER(dst), MSG_HEADER_SIZE(src));
    memcpy(MSG_HEADER_DATA(dst), MSG_HEADER_DATA(src), MSG_HEADER_SIZE(src));

    zmq_msg_init_size(MSG_CONTENT(dst), MSG_CONTENT_SIZE(src));
    memcpy(MSG_CONTENT_DATA(dst), MSG_CONTENT_DATA(src), MSG_CONTENT_SIZE(src));

    zmq_msg_init_size(MSG_META(dst), MSG_META_SIZE(src));
    memcpy(MSG_META_DATA(dst), MSG_META_DATA(src), MSG_META_SIZE(src));

    return 0;
}

spdnet_frame_t *spdnet_msg_get(struct spdnet_msg *msg, const char *frame_name)
{
    if (!strcmp(frame_name, "srcid"))
        return &msg->__srcid;
    else if (!strcmp(frame_name, "dstid"))
        return &msg->__dstid;
    else if (!strcmp(frame_name, "header"))
        return &msg->__header;
    else if (!strcmp(frame_name, "content"))
        return &msg->__content;
    else if (!strcmp(frame_name, "meta"))
        return &msg->__meta;
    return NULL;
}
