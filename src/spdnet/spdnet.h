#ifndef __ZEBRA_SPDNET_H
#define __ZEBRA_SPDNET_H

#include <pthread.h>
#include <zmq.h>

#ifdef __cplusplus
extern "C" {
#endif

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
 *     frame 1: node-type
 *     frame 2: dstid
 *     frame 3: delimiter
 *     frame 4: header
 *     frame 5: delimiter
 *     frame 6: content
 *     frame 7: delimiter
 *     frame 8: meta
 */

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

#define SPDNET_ERRNO_MAP(XX) \
	XX(EINVAL, "invalid argument") \
	XX(ESOCKETTYPE, "unsupported socket type") \
	XX(EPROTOCOL, "protocol error") \
	XX(EROUTING, "can't routing")

typedef enum {
	SPDNET_ERRNO_MIN = 10000,
#define XX(code, _) SPDNET_##code,
	SPDNET_ERRNO_MAP(XX)
#undef XX
	SPDNET_ERRNO_MAX = 11000,
} spdnet_errno_t;

const char *spdnet_strerror(int err);

#ifdef SPDNET_INTERNAL
	#include <extlist.h>
	#define spdnet_list_head list_head

	#ifdef SPDNET_DEBUG
	#include <stdio.h>
	#define LOG_DEBUG(format, ...) fprintf(stderr, format, ##__VA_ARGS__)
	#else
	#define LOG_DEBUG(format, ...)
	#endif
#else
	struct spdnet_list_head { void *prev, *next; };
#endif

/*
 * spdnet_msg
 */

typedef zmq_msg_t spdnet_frame_t;
typedef struct spdnet_meta {
	int node_type;
	int ttl;
} __attribute__((packed)) spdnet_meta_t;

struct spdnet_msg {
	spdnet_frame_t __sockid; // destid for sender, srcid for receiver
	spdnet_frame_t __header;
	spdnet_frame_t __content;
	spdnet_meta_t *__meta;
};

int spdnet_frame_init(spdnet_frame_t *frame);
int spdnet_frame_init_size(spdnet_frame_t *frame, size_t size);
int spdnet_frame_close(spdnet_frame_t *frame);
int spdnet_frame_move(spdnet_frame_t *dest, spdnet_frame_t *src);
int spdnet_frame_copy(spdnet_frame_t *dest, spdnet_frame_t *src);
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

void *spdnet_ctx_create(void);
int spdnet_ctx_destroy(void *ctx);

/*
 * zhelper
 */

int z_recv_more(void *s, spdnet_frame_t *frame, int flags);
int z_recv_not_more(void *s, spdnet_frame_t *frame, int flags);

/*
 * spdnet_node
 */

#define SPDNET_ROUTER ZMQ_ROUTER
#define SPDNET_NODE ZMQ_DEALER
#define SPDNET_SUB ZMQ_SUB
#define SPDNET_PUB ZMQ_PUB
#define SPDNET_OTHER -1

struct spdnet_node;
typedef void (*spdnet_recvmsg_cb)(struct spdnet_node *snode,
                                  struct spdnet_msg *msg);

struct spdnet_node {
	char id[SPDNET_SOCKID_SIZE];
	size_t id_len;

	int type;
	time_t alive_interval;
	time_t alive_timeout;

	char addr[SPDNET_ADDRESS_SIZE];
	void *socket;

	void *user_data;

	/* mainly used by spdnet_nodepool */
	spdnet_recvmsg_cb recvmsg_cb;
	time_t recvmsg_timeout;
	int count;
	int eof;
	struct spdnet_list_head node;
	struct spdnet_list_head pollin_node;
	struct spdnet_list_head pollout_node;
	struct spdnet_list_head pollerr_node;
	struct spdnet_list_head recvmsg_timeout_node;
};

int spdnet_node_init(struct spdnet_node *snode, int type, void *ctx);
int spdnet_node_init_socket(struct spdnet_node *snode, int type, void *socket);
int spdnet_node_close(struct spdnet_node *snode);
void *spdnet_node_get_socket(struct spdnet_node *snode);
int spdnet_setid(struct spdnet_node *snode, const void *id, size_t len);
void spdnet_setalive(struct spdnet_node *snode, time_t alive);
int spdnet_bind(struct spdnet_node *snode, const char *addr);
int spdnet_connect(struct spdnet_node *snode, const char *addr);
int spdnet_disconnect(struct spdnet_node *snode);
int spdnet_register(struct spdnet_node *snode);
int spdnet_unregister(struct spdnet_node *snode);
int spdnet_expose(struct spdnet_node *snode);
int spdnet_alive(struct spdnet_node *snode);
int spdnet_recv(struct spdnet_node *snode, void *buf, size_t size, int flags);
int spdnet_send(struct spdnet_node *snode, const void *buf,
                size_t size, int flags);
int spdnet_recvmsg(struct spdnet_node *snode, struct spdnet_msg *msg, int flags);
void spdnet_recvmsg_async(struct spdnet_node *snode,
                          spdnet_recvmsg_cb recvmsg_cb, long timeout);
int spdnet_sendmsg(struct spdnet_node *snode, struct spdnet_msg *msg);

/*
 * spdnet publish & subscribe
 */

int spdnet_publish_init(struct spdnet_node *pub, const char *addr, void *ctx);
int spdnet_publish_close(struct spdnet_node *pub);
int spdnet_subscribe_init(struct spdnet_node *sub, const char *addr, void *ctx);
int spdnet_subscribe_close(struct spdnet_node *sub);
int spdnet_subscribe_set_filter(struct spdnet_node *sub,
                                const void *prefix, size_t len);

/*
 * spdnet_nodepool
 */

struct spdnet_nodepool {
	void *ctx;
	int water_mark;
	int nr_snode;

	struct spdnet_list_head snodes;
	pthread_mutex_t snodes_lock;
	pthread_mutex_t snodes_del_lock;

	struct spdnet_list_head pollins;
	struct spdnet_list_head pollouts;
	struct spdnet_list_head pollerrs;
	struct spdnet_list_head recvmsg_timeouts;
};

int spdnet_nodepool_init(struct spdnet_nodepool *pool,
                         int water_mark, void *ctx);
int spdnet_nodepool_close(struct spdnet_nodepool *pool);
struct spdnet_node *
spdnet_nodepool_find(struct spdnet_nodepool *pool, const char *id);
struct spdnet_node *spdnet_nodepool_get(struct spdnet_nodepool *pool);
void spdnet_nodepool_put(struct spdnet_nodepool *pool,
                         struct spdnet_node *snode);
void spdnet_nodepool_add(struct spdnet_nodepool *pool,
                         struct spdnet_node *snode);
void spdnet_nodepool_del(struct spdnet_nodepool *pool,
                         struct spdnet_node *snode);
int spdnet_nodepool_loop(struct spdnet_nodepool *pool, long timeout);

/*
 * spdnet_router
 */

struct spdnet_routing_item {
	char id[SPDNET_SOCKID_SIZE];
	size_t len;

	char nexthop_id[SPDNET_SOCKID_SIZE];
	size_t nexthop_len;
	int nexthop_type;

	time_t atime;

	struct spdnet_list_head node;
};

#define INIT_SPDNET_ROUTING_ITEM( \
	item, _id, _len, _nexthop_id, _nexthop_len, _nexthop_type) \
	do { \
		memset(item, 0, sizeof(*item)); \
		item->len = _len; \
		memcpy(item->id, _id, item->len); \
		item->nexthop_len = _nexthop_len; \
		memcpy(item->nexthop_id, _nexthop_id, item->nexthop_len); \
		item->nexthop_type = _nexthop_type; \
		item->atime = time(NULL); \
		INIT_LIST_HEAD(&item->node); \
	} while (0);

struct spdnet_router {
	void *ctx;
	struct spdnet_node snode;
	struct spdnet_list_head routing_table;

	int nr_msg_routerd;
	int nr_msg_dropped;
};

int spdnet_router_init(struct spdnet_router *router, const char *id, void *ctx);
int spdnet_router_close(struct spdnet_router *router);
int spdnet_router_bind(struct spdnet_router *router, const char *addr);
int spdnet_router_associate(struct spdnet_router *router,
                            const char *addr, void *id, size_t *len);
int spdnet_router_set_gateway(struct spdnet_router *router,
                              void *id, size_t len, int type);
int spdnet_router_msg_routerd(struct spdnet_router *router);
int spdnet_router_msg_dropped(struct spdnet_router *router);
int spdnet_router_loop(struct spdnet_router *router, long timeout);

#ifdef __cplusplus
}
#endif
#endif
