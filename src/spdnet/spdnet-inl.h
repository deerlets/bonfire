#ifndef __SPDNET_SPDNET_INL_H
#define __SPDNET_SPDNET_INL_H

#include <pthread.h>
#include <zmq.h>
#include "list.h"

#define SPDNET_ROUTER_DEFAULT_GATEWAY "default_gateway"
#define SPDNET_ROUTING_ITEM_STALL 3600
#define SPDNET_ALIVE_INTERVAL 600
#define SPDNET_MIN_ALIVE_INTERVAL 10

typedef zmq_msg_t spdnet_frame_t;
#include "spdnet.h"

void z_clear(void *s);
int z_recv_more(void *s, spdnet_frame_t *frame, int flags);
int z_recv_not_more(void *s, spdnet_frame_t *frame, int flags);

struct spdnet_ctx {
	void *zmq_ctx;
	struct spdnet_pool *pool;
};

struct spdnet_interface {
	struct spdnet_node *(*create)(struct spdnet_ctx *ctx);
	void (*destroy)(struct spdnet_node *snode);
	int (*recvmsg)(struct spdnet_node *snode, struct spdnet_msg *msg);
	int (*sendmsg)(struct spdnet_node *snode, struct spdnet_msg *msg);

	int (*associate)(struct spdnet_node *snode, const char *addr,
	                 char *buf_id, size_t buf_len);
	int (*set_gateway)(struct spdnet_node *snode, const char *id);
};

struct spdnet_node {
	struct spdnet_ctx *ctx;

	char *id;

	int type;
	struct spdnet_interface *ifs;

	int64_t alive_interval;
	int64_t alive_timeout;

	int is_bind;
	int is_connect;
	char bind_addr[SPDNET_ADDR_SIZE];
	char connect_addr[SPDNET_ADDR_SIZE];
	void *socket;

	void *user_data;

	/* mainly used by spdnet_pool */
	int used;
	spdnet_recvmsg_cb recvmsg_cb;
	void *recvmsg_arg;
	int64_t recvmsg_timeout;
	struct list_head node;
	struct list_head pollin_node;
	struct list_head pollout_node;
	struct list_head pollerr_node;
	struct list_head recvmsg_timeout_node;
};

int spdnet_node_init(struct spdnet_node *snode, struct spdnet_ctx *ctx, int type);
void spdnet_node_fini(struct spdnet_node *snode);
int spdnet_register(struct spdnet_node *snode);
int spdnet_unregister(struct spdnet_node *snode);
int spdnet_alive(struct spdnet_node *snode);

struct spdnet_interface *spdnet_dealer_interface();
struct spdnet_interface *spdnet_router_interface();
struct spdnet_interface *spdnet_pub_interface();
struct spdnet_interface *spdnet_sub_interface();

struct spdnet_pool {
	struct spdnet_ctx *ctx;
	int water_mark;

	int nr_snode;
	struct list_head snodes;
	pthread_mutex_t snodes_lock;

	struct list_head pollins;
	struct list_head pollouts;
	struct list_head pollerrs;
	struct list_head recvmsg_timeouts;
	pthread_mutex_t polls_lock;
};

struct spdnet_pool *spdnet_pool_new(struct spdnet_ctx *ctx, int water_mark);
void spdnet_pool_destroy(struct spdnet_pool *pool);
void spdnet_pool_add(struct spdnet_pool *pool, struct spdnet_node *snode);
void spdnet_pool_del(struct spdnet_pool *pool, struct spdnet_node *snode);
void *spdnet_pool_get(struct spdnet_pool *pool, int type);
void spdnet_pool_put(struct spdnet_pool *pool, struct spdnet_node *snode);
int spdnet_pool_alive_count(struct spdnet_pool *pool);
int spdnet_pool_loop(struct spdnet_pool *pool, long timeout);

#endif
