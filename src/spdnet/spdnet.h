#ifndef __SPDNET_SPDNET_H
#define __SPDNET_SPDNET_H

/*
 * spdnet protocol - node to router:
 *     frame 1: srcid
 *     frame 2: node-type
 *     frame 3: dstid
 *     frame 4: delimiter
 *     frame 5: header
 *     frame 6: delimiter
 *     frame 7: content
 *     frame 8: delimiter
 *     frame 9: meta
 *
 * spdnet protocol - router to node:
 *     frame 1: rid
 *     frame 2: node-type
 *     frame 3: srcid
 *     frame 4: delimiter
 *     frame 5: header
 *     frame 6: delimiter
 *     frame 7: content
 *     frame 8: self-rid
 *     frame 9: meta
 *
 * spdnet protocol - router to router:
 *     frame 1: rid
 *     frame 2: node-type
 *     frame 3: srcid
 *     frame 4: delimiter
 *     frame 5: dstid
 *     frame 6: delimiter
 *     frame 7: header
 *     frame 8: delimiter
 *     frame 9: content
 *     frame 10: self-rid
 *     frame 11: meta
 *
 * spdnet protocol - pub to sub:
 *     frame 1: topic
 *     frame 2: delimiter
 *     frame 3: empty | delimiter
 *     frame 4: delimiter
 *     frame 5: content
 *     frame 6: delimiter
 *     frame 7: meta
 */

#include <stddef.h> // size_t
#include <stdint.h> // int64_t

#ifdef __cplusplus
extern "C" {
#endif

#define SPDNET_SOCKID_NONE "--none--"
#define SPDNET_SOCKID_NONE_LEN (sizeof(SPDNET_SOCKID_NONE)-1)
#define SPDNET_REGISTER_MSG "snode-register"
#define SPDNET_REGISTER_MSG_LEN (sizeof(SPDNET_REGISTER_MSG)-1)
#define SPDNET_UNREGISTER_MSG "snode-unregister"
#define SPDNET_UNREGISTER_MSG_LEN (sizeof(SPDNET_UNREGISTER_MSG)-1)
#define SPDNET_EXPOSE_MSG "snode-expose"
#define SPDNET_EXPOSE_MSG_LEN (sizeof(SPDNET_EXPOSE_MSG)-1)
#define SPDNET_ALIVE_MSG "snode-alive"
#define SPDNET_ALIVE_MSG_LEN (sizeof(SPDNET_ALIVE_MSG)-1)

#define SPDNET_ROUTER_DEFAULT_GATEWAY "default_gateway"
#define SPDNET_ROUTING_ITEM_STALL 3600
#define SPDNET_ALIVE_INTERVAL 600
#define SPDNET_MIN_ALIVE_INTERVAL 10

#define SPDNET_ZMTP_SOCKID_LEN 5
#define SPDNET_SOCKID_SIZE 64
#define SPDNET_ADDRESS_SIZE 64

/*
 * spdnet errno & errmsg
 */

#define SPDNET_ERRNO_MAP(XX) \
	XX(EINVAL, "invalid argument") \
	XX(ESOCKETTYPE, "unsupported socket type") \
	XX(EPROTOCOL, "protocol error") \
	XX(EROUTING, "can't routing") \
	XX(EIO, "recv or send error")

typedef enum {
	SPDNET_ERRNO_MIN = 10000,
#define XX(code, _) SPDNET_##code,
	SPDNET_ERRNO_MAP(XX)
#undef XX
	SPDNET_ERRNO_MAX = 11000,
} spdnet_errno_t;

const char *spdnet_strerror(int err);

/*
 * spdnet_msg
 */

#ifndef __SPDNET_SPDNET_INTERNAL_H
typedef struct spdnet_frame_t
{
#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_ARM64))
	__declspec(align (8)) unsigned char _[64];
#elif defined(_MSC_VER) && (defined(_M_IX86) || defined(_M_ARM_ARMV7VE))
	__declspec(align (4)) unsigned char _[64];
#elif defined(__GNUC__) || defined(__INTEL_COMPILER) \
	|| (defined(__SUNPRO_C) && __SUNPRO_C >= 0x590) \
	|| (defined(__SUNPRO_CC) && __SUNPRO_CC >= 0x590)
	unsigned char _[64] __attribute__ ((aligned (sizeof (void *))));
#else
	unsigned char _[64];
#endif
} spdnet_frame_t;
#endif

typedef struct spdnet_meta {
	int node_type;
	int ttl;
} __attribute__((packed)) spdnet_meta_t;

struct spdnet_msg {
	spdnet_frame_t __sockid; // dstid for sender, srcid for receiver
	spdnet_frame_t __header;
	spdnet_frame_t __content;
	spdnet_meta_t *__meta;
};

int spdnet_frame_init(spdnet_frame_t *frame);
int spdnet_frame_init_size(spdnet_frame_t *frame, size_t size);
int spdnet_frame_close(spdnet_frame_t *frame);
int spdnet_frame_move(spdnet_frame_t *dst, spdnet_frame_t *src);
int spdnet_frame_copy(spdnet_frame_t *dst, spdnet_frame_t *src);
void *spdnet_frame_data(spdnet_frame_t *frame);
size_t spdnet_frame_size(const spdnet_frame_t *frame);

int spdnet_msg_init(struct spdnet_msg *msg);
int spdnet_msg_init_data(struct spdnet_msg *msg,
                         const void *sockid, int id_size,
                         const void *header, int hdr_size,
                         const void *content, int cnt_size);
int spdnet_msg_close(struct spdnet_msg *msg);
int spdnet_msg_move(struct spdnet_msg *dst, struct spdnet_msg *src);
int spdnet_msg_copy(struct spdnet_msg *dst, struct spdnet_msg *src);
spdnet_frame_t *spdnet_msg_get(struct spdnet_msg *msg, const char *frame_name);

#define SPDNET_MSG_INIT_DATA(msg, sockid, header, content) \
	spdnet_msg_init_data(msg, sockid, -1, header, -1, content, -1)

#define MSG_SOCKID(msg) spdnet_msg_get(msg, "sockid")
#define MSG_SOCKID_DATA(msg) spdnet_frame_data(spdnet_msg_get(msg, "sockid"))
#define MSG_SOCKID_SIZE(msg) spdnet_frame_size(spdnet_msg_get(msg, "sockid"))

#define MSG_HEADER(msg) spdnet_msg_get(msg, "header")
#define MSG_HEADER_DATA(msg) spdnet_frame_data(spdnet_msg_get(msg, "header"))
#define MSG_HEADER_SIZE(msg) spdnet_frame_size(spdnet_msg_get(msg, "header"))

#define MSG_CONTENT(msg) spdnet_msg_get(msg, "content")
#define MSG_CONTENT_DATA(msg) spdnet_frame_data(spdnet_msg_get(msg, "content"))
#define MSG_CONTENT_SIZE(msg) spdnet_frame_size(spdnet_msg_get(msg, "content"))

/*
 * spdnet_ctx
 */

void *spdnet_ctx_new(void);
int spdnet_ctx_destroy(void *ctx);

/*
 * spdnet_node
 */

#define SPDNET_PUB 1
#define SPDNET_SUB 2
#define SPDNET_NODE 5

void *spdnet_node_new(void *ctx, int type);
int spdnet_node_destroy(void *snode);

void *spdnet_get_socket(void *__snode);
void spdnet_get_id(void *snode, void *id, size_t *len);
void spdnet_set_id(void *snode, const void *id, size_t len);
void spdnet_set_alive(void *snode, int64_t alive);
void spdnet_set_filter(void *__snode, const void *prefix, size_t len);

int spdnet_bind(void *snode, const char *addr);
int spdnet_connect(void *snode, const char *addr);
int spdnet_disconnect(void *snode);

int spdnet_register(void *snode);
int spdnet_unregister(void *snode);
int spdnet_expose(void *snode);
int spdnet_alive(void *snode);

int spdnet_recv(void *snode, void *buf, size_t size, int flags);
int spdnet_send(void *snode, const void *buf, size_t size, int flags);

typedef void (*spdnet_recvmsg_cb)(
	void *snode, struct spdnet_msg *msg, void *arg);

int spdnet_recvmsg(void *snode, struct spdnet_msg *msg, int flags);
int spdnet_recvmsg_timeout(void *snode, struct spdnet_msg *msg,
                           int flags, int timeout);
void spdnet_recvmsg_async(void *snode, spdnet_recvmsg_cb recvmsg_cb,
                          void *arg, long timeout);
int spdnet_sendmsg(void *snode, struct spdnet_msg *msg);

/*
 * spdnet_forwarder
 */

void *
spdnet_forwarder_new(void *ctx, const char *pub_addr, const char *sub_addr);
void spdnet_forwarder_destroy(void *fwd);
int spdnet_forwarder_loop(void *fwd, long timeout);

/*
 * spdnet_router
 */

void *spdnet_router_new(void *ctx, const char *id);
int spdnet_router_destroy(void *router);
int spdnet_router_bind(void *router, const char *addr);
int
spdnet_router_associate(void *router, const char *addr, void *id, size_t *len);
int spdnet_router_set_gateway(void *router, void *id, size_t len);
int spdnet_router_msg_routerd(void *router);
int spdnet_router_msg_dropped(void *router);
int spdnet_router_loop(void *router, long timeout);

/*
 * spdnet_nodepool
 */

void *spdnet_nodepool_new(void *ctx, int water_mark);
int spdnet_nodepool_destroy(void *pool);
void *spdnet_nodepool_find(void *pool, const void *id, size_t len);
void *spdnet_nodepool_get(void *pool);
void spdnet_nodepool_put(void *pool, void *snode);
void spdnet_nodepool_add(void *pool, void *snode);
void spdnet_nodepool_del(void *pool, void *snode);
int spdnet_nodepool_alive_count(void *pool);
int spdnet_nodepool_loop(void *pool, long timeout);

#ifdef __cplusplus
}
#endif
#endif
