#ifndef __ZERO_SPDNET_H
#define __ZERO_SPDNET_H

#include <time.h>
#include <limits.h>
#include <zmq.h>
#include "list.h"
#include "mutex.h"

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
#define SPDNET_ALIVE_MSG "snode-alive"
#define SPDNET_ALIVE_MSG_LEN (sizeof(SPDNET_ALIVE_MSG)-1)

#define SPDNET_ROUTER_DEFAULT_GATEWAY "default_gateway"
#define SPDNET_ROUTING_ITEM_STALL 3600
#define SPDNET_ALIVE_INTERVAL 600
#define SPDNET_MIN_ALIVE_INTERVAL 10

#define SPDNET_ZMTP_SOCKID_LEN 5
#define SPDNET_SOCKID_SIZE 16
#define SPDNET_NAME_SIZE 1024
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

/*
 * spdnet_msg
 */

typedef struct spdnet_meta {
	char name[SPDNET_NAME_SIZE];
	int node_type;
	int ttl;
} spdnet_meta_t;

struct spdnet_msg {
	zmq_msg_t __sockid; // destid for sender, srcid for receiver
	zmq_msg_t __header;
	zmq_msg_t __content;
	spdnet_meta_t __meta;
};

int spdnet_msg_init(struct spdnet_msg *msg);
int spdnet_msg_init_data(struct spdnet_msg *msg,
                         const void *sockid, int id_size,
                         const void *header, int hdr_size,
                         const void *content, int cnt_size);
int spdnet_msg_close(struct spdnet_msg *msg);
int spdnet_msg_move(struct spdnet_msg *dst, struct spdnet_msg *src);
int spdnet_msg_copy(struct spdnet_msg *dst, struct spdnet_msg *src);
zmq_msg_t *spdnet_msg_get(struct spdnet_msg *msg, const char *name);
const char *spdnet_msg_gets(struct spdnet_msg *msg, const char *property);
int spdnet_msg_sets(struct spdnet_msg *msg, const char *property,
                    const char *value);

#define SPDNET_MSG_INIT_DATA(msg, sockid, header, content) \
	spdnet_msg_init_data(msg, sockid, -1, header, -1, content, -1)
#define MSG_SOCKID(msg) spdnet_msg_get(msg, "sockid")
#define MSG_HEADER(msg) spdnet_msg_get(msg, "header")
#define MSG_CONTENT(msg) spdnet_msg_get(msg, "content")

/*
 * spdnet_ctx
 */

void *spdnet_ctx_create(void);
int spdnet_ctx_destroy(void *ctx);

/*
 * zhelper
 */

int z_recv_more(void *s, zmq_msg_t *msg, int flags);
int z_recv_not_more(void *s, zmq_msg_t *msg, int flags);

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

	char name[SPDNET_NAME_SIZE];
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
	struct list_head node;
	struct list_head pollin_node;
	struct list_head pollout_node;
	struct list_head pollerr_node;
	struct list_head recvmsg_timeout_node;
};

int spdnet_node_init(struct spdnet_node *snode, int type, void *ctx);
int spdnet_node_init_socket(struct spdnet_node *snode, int type, void *socket);
int spdnet_node_close(struct spdnet_node *snode);
void *spdnet_node_get_socket(struct spdnet_node *snode);
int spdnet_setid(struct spdnet_node *snode, const void *id, size_t len);
void spdnet_setname(struct spdnet_node *snode, const char *name);
void spdnet_setalive(struct spdnet_node *snode, time_t alive);
const char *spdnet_getname(struct spdnet_node *snode);
int spdnet_bind(struct spdnet_node *snode, const char *addr);
int spdnet_connect(struct spdnet_node *snode, const char *addr);
int spdnet_disconnect(struct spdnet_node *snode);
int spdnet_register(struct spdnet_node *snode);
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

static inline int
spdnet_publish_init(struct spdnet_node *pub, const char *addr, void *ctx)
{
	if (spdnet_node_init(pub, SPDNET_PUB, ctx))
		return -1;

	if (spdnet_bind(pub, addr)) {
		spdnet_node_close(pub);
		return -1;
	}

	return 0;
}

static inline int
spdnet_publish_close(struct spdnet_node *pub)
{
	return spdnet_node_close(pub);
}

static inline int
spdnet_subscribe_init(struct spdnet_node *sub, const char *addr, void *ctx)
{
	if (spdnet_node_init(sub, SPDNET_SUB, ctx))
		return -1;

	if (spdnet_connect(sub, addr)) {
		spdnet_node_close(sub);
		return -1;
	}

	return 0;
}

static inline int
spdnet_subscribe_close(struct spdnet_node *sub)
{
	return spdnet_node_close(sub);
}

static inline int
spdnet_subscribe_set_filter(struct spdnet_node *sub,
                            const void *prefix, size_t len)
{
	return zmq_setsockopt(sub->socket, ZMQ_SUBSCRIBE, prefix, len);
}

/*
 * spdnet_multicast
 */

struct spdnet_multicast {
	struct spdnet_node sub;
	struct spdnet_node pub;
};

int spdnet_multicast_init(struct spdnet_multicast *mc,
                          const char *pgm_addr, int hops, void *ctx);
int spdnet_multicast_close(struct spdnet_multicast *mc);
int spdnet_multicast_recv(struct spdnet_multicast *mc,
                          struct spdnet_msg *msg, int flags);
int spdnet_multicast_send(struct spdnet_multicast *mc, struct spdnet_msg *msg);

/*
 * spdnet_nodepool
 */

struct spdnet_nodepool {
	void *ctx;
	int water_mark;
	int nr_snode;

	struct list_head snodes;
	mutex_t snodes_lock;

	struct list_head pollins;
	struct list_head pollouts;
	struct list_head pollerrs;
	struct list_head recvmsg_timeouts;
};

int spdnet_nodepool_init(struct spdnet_nodepool *pool,
                         int water_mark, void *ctx);
int spdnet_nodepool_close(struct spdnet_nodepool *pool);
struct spdnet_node *
spdnet_nodepool_find(struct spdnet_nodepool *pool, const char *name);
struct spdnet_node *spdnet_nodepool_get(struct spdnet_nodepool *pool);
void spdnet_nodepool_put(struct spdnet_nodepool *pool,
                         struct spdnet_node *snode);
void spdnet_nodepool_add(struct spdnet_nodepool *pool,
                         struct spdnet_node *snode);
void spdnet_nodepool_del(struct spdnet_nodepool *pool,
                         struct spdnet_node *snode);
int spdnet_nodepool_poll(struct spdnet_nodepool *pool, long timeout);
int spdnet_nodepool_run(struct spdnet_nodepool *pool);

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

	struct list_head node;
};

#define INIT_SPDNET_ROUTING_ITEM(item, _id, _len, \
	_nexthop_id, _nexthop_len, _nexthop_type) \
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
	struct list_head routing_table;

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
int spdnet_router_run(struct spdnet_router *router);

#ifdef __cplusplus
}
#endif
#endif
