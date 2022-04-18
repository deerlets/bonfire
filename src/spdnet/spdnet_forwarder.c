#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include "spdnet-inl.h"

struct spdnet_forwarder {
    void *pub;
    void *sub;
};

static void forwarder_cb(struct spdnet_node *snode, struct spdnet_msg *msg,
                         void *arg, int flag)
{
    if (flag) {
        fprintf(stderr, "[%s]: flag => %d\n", __func__, flag);
        return;
    }
    assert(msg);
    struct spdnet_forwarder *fwd = arg;

#ifdef SPDNET_DEBUG
    char *topic = calloc(1, MSG_DSTID_SIZE(msg) + 1);
    char *content = calloc(1, MSG_CONTENT_SIZE(msg) + 1);
    memcpy(topic, MSG_DSTID_DATA(msg), MSG_DSTID_SIZE(msg));
    memcpy(content, MSG_CONTENT_DATA(msg), MSG_CONTENT_SIZE(msg));

    struct timeval tmnow;
    char buf[32] = {0}, usec_buf[16] = {0};
    gettimeofday(&tmnow, NULL);
    strftime(buf, 30, "%Y-%m-%d %H:%M:%S", localtime(&tmnow.tv_sec));
    sprintf(usec_buf, ".%04d", (int)tmnow.tv_usec / 100);
    strcat(buf, usec_buf);

    fprintf(stderr, "[%s] - fwdid=%p, topic=%s, content=%s\n",
            buf, fwd, topic, content);

    free(topic);
    free(content);
#endif

    spdnet_sendmsg(fwd->pub, msg);
    spdnet_recvmsg_async(fwd->sub, forwarder_cb, fwd, 0);
}

struct spdnet_forwarder *spdnet_forwarder_new(struct spdnet_ctx *ctx)
{
    struct spdnet_forwarder *fwd = malloc(sizeof(*fwd));
    if (!fwd) return NULL;

    fwd->pub = spdnet_node_new(ctx, SPDNET_PUB);
    fwd->sub = spdnet_node_new(ctx, SPDNET_SUB);

    spdnet_recvmsg_async(fwd->sub, forwarder_cb, fwd, 0);
    return fwd;
}

void spdnet_forwarder_destroy(struct spdnet_forwarder *fwd)
{
    spdnet_node_destroy(fwd->pub);
    spdnet_node_destroy(fwd->sub);
    free(fwd);
}

int spdnet_forwarder_bind(struct spdnet_forwarder *fwd, const char *pub_addr,
                          const char *sub_addr)
{
    if (spdnet_bind(fwd->pub, pub_addr))
        return -1;

    if (spdnet_bind(fwd->sub, sub_addr))
        return -1;

    spdnet_set_filter(fwd->sub, "", 0);

    return 0;
}
