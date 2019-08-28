#ifndef __SPDNET_SPDNET_H
#define __SPDNET_SPDNET_H

/*
 * spdnet protocol - node to router:
 *     frame 1: srcid(send:auto add, recv:manual)
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
 *     frame 1: dstid(send:manual, recv:auto remove)
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
 *     frame 1: next-rid(send), prev-rid(recv)
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
 *     frame 3: content
 *     frame 4: delimiter
 *     frame 5: meta
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

#define SPDNET_ZMTP_DSTID_LEN 5
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
	XX(EIO, "recv or send error") \
	XX(ETIMEOUT, "recv timeout")

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

#ifndef __SPDNET_SPDNET_INL_H
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
	spdnet_frame_t __srcid;
	spdnet_frame_t __dstid;
	spdnet_frame_t __header;
	spdnet_frame_t __content;
	spdnet_frame_t __meta;
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
                         const void *dstid, int id_size,
                         const void *header, int hdr_size,
                         const void *content, int cnt_size);
int spdnet_msg_close(struct spdnet_msg *msg);
int spdnet_msg_move(struct spdnet_msg *dst, struct spdnet_msg *src);
int spdnet_msg_copy(struct spdnet_msg *dst, struct spdnet_msg *src);
spdnet_frame_t *spdnet_msg_get(struct spdnet_msg *msg, const char *frame_name);

#define SPDNET_MSG_INIT_DATA(msg, dstid, header, content) \
	spdnet_msg_init_data(msg, dstid, -1, header, -1, content, -1)

#define MSG_SRCID(msg) spdnet_msg_get(msg, "srcid")
#define MSG_SRCID_DATA(msg) spdnet_frame_data(spdnet_msg_get(msg, "srcid"))
#define MSG_SRCID_SIZE(msg) spdnet_frame_size(spdnet_msg_get(msg, "srcid"))

#define MSG_DSTID(msg) spdnet_msg_get(msg, "dstid")
#define MSG_DSTID_DATA(msg) spdnet_frame_data(spdnet_msg_get(msg, "dstid"))
#define MSG_DSTID_SIZE(msg) spdnet_frame_size(spdnet_msg_get(msg, "dstid"))

#define MSG_HEADER(msg) spdnet_msg_get(msg, "header")
#define MSG_HEADER_DATA(msg) spdnet_frame_data(spdnet_msg_get(msg, "header"))
#define MSG_HEADER_SIZE(msg) spdnet_frame_size(spdnet_msg_get(msg, "header"))

#define MSG_CONTENT(msg) spdnet_msg_get(msg, "content")
#define MSG_CONTENT_DATA(msg) spdnet_frame_data(spdnet_msg_get(msg, "content"))
#define MSG_CONTENT_SIZE(msg) spdnet_frame_size(spdnet_msg_get(msg, "content"))

#define MSG_META(msg) spdnet_msg_get(msg, "meta")
#define MSG_META_DATA(msg) spdnet_frame_data(spdnet_msg_get(msg, "meta"))
#define MSG_META_SIZE(msg) spdnet_frame_size(spdnet_msg_get(msg, "meta"))

/*
 * spdnet_ctx
 */

struct spdnet_ctx;

struct spdnet_ctx *spdnet_ctx_new(void);
void spdnet_ctx_destroy(struct spdnet_ctx *ctx);
int spdnet_loop(struct spdnet_ctx *ctx, long timeout);

/*
 * spdnet_node
 */

#define SPDNET_PUB 1
#define SPDNET_SUB 2
#define SPDNET_DEALER 5
#define SPDNET_ROUTER 6

struct spdnet_node;

struct spdnet_node *spdnet_node_new(struct spdnet_ctx *ctx, int type);
void spdnet_node_destroy(struct spdnet_node *snode);

void *spdnet_get_socket(struct spdnet_node *snode);
void spdnet_get_id(struct spdnet_node *snode, void *id, size_t *len);
void spdnet_set_id(struct spdnet_node *snode, const void *id, size_t len);
void spdnet_set_alive(struct spdnet_node *snode, int64_t alive);
void spdnet_set_filter(struct spdnet_node *snode, const void *prefix, size_t len);
void *spdnet_get_user_data(struct spdnet_node *snode);
void spdnet_set_user_data(struct spdnet_node *snode, void *user_data);

int spdnet_bind(struct spdnet_node *snode, const char *addr);
int spdnet_connect(struct spdnet_node *snode, const char *addr);
void spdnet_unbind(struct spdnet_node *snode);
void spdnet_disconnect(struct spdnet_node *snode);

int spdnet_register(struct spdnet_node *snode);
int spdnet_unregister(struct spdnet_node *snode);
int spdnet_expose(struct spdnet_node *snode);
int spdnet_alive(struct spdnet_node *snode);

int spdnet_associate(struct spdnet_node *snode,
                     const char *addr, void *id, size_t *len);
int spdnet_set_gateway(struct spdnet_node *snode, void *id, size_t len);

typedef void (*spdnet_recvmsg_cb)(
	struct spdnet_node *snode, struct spdnet_msg *msg, void *arg, int flag);

int spdnet_recvmsg(struct spdnet_node *snode, struct spdnet_msg *msg);
int spdnet_recvmsg_timeout(struct spdnet_node *snode,
                           struct spdnet_msg *msg, int timeout);
void spdnet_recvmsg_async(struct spdnet_node *snode, spdnet_recvmsg_cb cb,
                          void *arg, long timeout);
int spdnet_sendmsg(struct spdnet_node *snode, struct spdnet_msg *msg);

/*
 * spdnet_forwarder
 */

struct spdnet_forwarder;

struct spdnet_forwarder *spdnet_forwarder_new(struct spdnet_ctx *ctx);
void spdnet_forwarder_destroy(struct spdnet_forwarder *fwd);
int spdnet_forwarder_bind(struct spdnet_forwarder *fwd,
                          const char *pub_addr, const char *sub_addr);

#ifdef __cplusplus
}
#endif
#endif
