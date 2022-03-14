#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include "spdnet-inl.h"

static struct spdnet_node *spdnet_pub_create(struct spdnet_ctx *ctx)
{
    struct spdnet_node *snode = malloc(sizeof(*snode));
    if (!snode) return NULL;
    if (spdnet_node_init(snode, ctx, SPDNET_PUB)) {
        free(snode);
        return NULL;
    }
    snode->ifs = spdnet_pub_interface();
    return snode;
}

static struct spdnet_node *spdnet_sub_create(struct spdnet_ctx *ctx)
{
    struct spdnet_node *snode = malloc(sizeof(*snode));
    if (!snode) return NULL;
    if (spdnet_node_init(snode, ctx, SPDNET_SUB)) {
        free(snode);
        return NULL;
    }
    snode->ifs = spdnet_sub_interface();
    return snode;
}

static void spdnet_pub_sub_destroy(struct spdnet_node *snode)
{
    spdnet_node_fini(snode);
    free(snode);
}

static int
spdnet_pub_sub_recvmsg(struct spdnet_node *snode, struct spdnet_msg *msg)
{
    int rc = 0;

    // topic
    rc = z_recv_more(snode->socket, MSG_HEADER(msg), 0);
    if (rc == -1) return -1;

    // content
    rc = z_recv_more(snode->socket, MSG_CONTENT(msg), 0);
    if (rc == -1) return -1;
    rc = z_recv_more(snode->socket, MSG_CONTENT(msg), 0);
    if (rc == -1) return -1;

    // meta
    rc = z_recv_more(snode->socket, MSG_META(msg), 0);
    if (rc == -1) return -1;
    rc = z_recv_not_more(snode->socket, MSG_META(msg), 0);
    if (rc == -1) {
        z_clear(snode->socket);
        return -1;
    }

    return 0;
}

static int
spdnet_pub_sub_sendmsg(struct spdnet_node *snode, struct spdnet_msg *msg)
{
    int rc = 0;

    // topic
    rc = zmq_msg_send(MSG_HEADER(msg), snode->socket, ZMQ_SNDMORE);
    if (rc == -1) return -1;

    // content
    rc = zmq_send(snode->socket, "", 0, ZMQ_SNDMORE);
    if (rc == -1) return -1;
    rc = zmq_msg_send(MSG_CONTENT(msg), snode->socket, ZMQ_SNDMORE);
    if (rc == -1) return -1;

    // meta
    rc = zmq_send(snode->socket, "", 0, ZMQ_SNDMORE);
    if (rc == -1) return -1;

    spdnet_meta_t meta;
    meta.node_type = snode->type;
    meta.ttl = 10;

    zmq_msg_close(MSG_META(msg));
    zmq_msg_init_size(MSG_META(msg), sizeof(meta));
    memcpy(MSG_META_DATA(msg), &meta, sizeof(meta));
    rc = zmq_msg_send(MSG_META(msg), snode->socket, 0);
    if (rc == -1) return -1;

    return 0;
}

static struct spdnet_interface pub_if = {
    .create = spdnet_pub_create,
    .destroy = spdnet_pub_sub_destroy,
    .recvmsg = spdnet_pub_sub_recvmsg,
    .sendmsg = spdnet_pub_sub_sendmsg,
};

struct spdnet_interface *spdnet_pub_interface()
{
    return &pub_if;
}

static struct spdnet_interface sub_if = {
    .create = spdnet_sub_create,
    .destroy = spdnet_pub_sub_destroy,
    .recvmsg = spdnet_pub_sub_recvmsg,
    .sendmsg = spdnet_pub_sub_sendmsg,
};

struct spdnet_interface *spdnet_sub_interface()
{
    return &sub_if;
}
