#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include "spdnet-inl.h"

static struct spdnet_node *spdnet_dealer_create(struct spdnet_ctx *ctx)
{
    struct spdnet_node *snode = malloc(sizeof(*snode));
    if (!snode) return NULL;
    if (spdnet_node_init(snode, ctx, SPDNET_DEALER)) {
        free(snode);
        return NULL;
    }
    snode->ifs = spdnet_dealer_interface();
    return snode;
}

static void spdnet_dealer_destroy(struct spdnet_node *snode)
{
    spdnet_node_fini(snode);
    free(snode);
}

static int
spdnet_dealer_recvmsg(struct spdnet_node *snode, struct spdnet_msg *msg)
{
    int rc = 0;

    // srcid
    rc = z_recv_more(snode->socket, MSG_SRCID(msg), 0);
    if (rc == -1) return -1;
    rc = z_recv_more(snode->socket, MSG_SRCID(msg), 0);
    if (rc == -1) return -1;

    // dstid
    spdnet_frame_close(MSG_DSTID(msg));
    spdnet_frame_init_size(MSG_DSTID(msg), strlen(snode->id));
    memcpy(MSG_DSTID_DATA(msg), snode->id, strlen(snode->id));

    // header
    rc = z_recv_more(snode->socket, MSG_HEADER(msg), 0);
    if (rc == -1) return -1;
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
spdnet_dealer_sendmsg(struct spdnet_node *snode, struct spdnet_msg *msg)
{
    int rc = 0;

    // dstid
    rc = zmq_send(snode->socket, &snode->type, 1,
                  ZMQ_SNDMORE | ZMQ_DONTWAIT);
    if (rc == -1) return -1;
    rc = zmq_msg_send(MSG_DSTID(msg), snode->socket, ZMQ_SNDMORE);
    if (rc == -1) return -1;

    // header
    rc = zmq_send(snode->socket, "", 0, ZMQ_SNDMORE);
    if (rc == -1) return -1;
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

static struct spdnet_interface dealer_if = {
    .create = spdnet_dealer_create,
    .destroy = spdnet_dealer_destroy,
    .recvmsg = spdnet_dealer_recvmsg,
    .sendmsg = spdnet_dealer_sendmsg,
};

struct spdnet_interface *spdnet_dealer_interface()
{
    return &dealer_if;
}
