#ifndef __SPDNET_SPDNET_INL_H
#define __SPDNET_SPDNET_INL_H

#include <pthread.h>
#include <zmq.h>
#include "list.h"

#define SPDNET_PUB 1 // ZMQ_PUB
#define SPDNET_SUB 2 // ZMQ_SUB
#define SPDNET_NODE 5 // ZMQ_DEALER
#define SPDNET_ROUTER 6 // ZMQ_ROUTER
#define SPDNET_OTHER -1

typedef zmq_msg_t spdnet_frame_t;
#include "spdnet.h"

void z_clear(void *s);
int z_recv_more(void *s, spdnet_frame_t *frame, int flags);
int z_recv_not_more(void *s, spdnet_frame_t *frame, int flags);

struct spdnet_ctx {
	void *zmq_ctx;
	struct spdnet_nodepool *pool;
};

struct spdnet_node {
	struct spdnet_ctx *ctx;

	char id[SPDNET_SOCKID_SIZE];
	size_t id_len;

	int type;
	int64_t alive_interval;
	int64_t alive_timeout;

	int is_bind;
	int is_connect;
	char bind_addr[SPDNET_ADDRESS_SIZE];
	char connect_addr[SPDNET_ADDRESS_SIZE];
	void *socket;

	void *user_data;

	/* mainly used by spdnet_nodepool */
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

struct spdnet_nodepool {
	struct spdnet_ctx *ctx;
	int water_mark;
	int nr_snode;

	struct list_head snodes;
	pthread_mutex_t snodes_lock;
	pthread_mutex_t snodes_del_lock;

	struct list_head pollins;
	struct list_head pollouts;
	struct list_head pollerrs;
	struct list_head recvmsg_timeouts;
};

void *spdnet_nodepool_new(struct spdnet_ctx *ctx, int water_mark);
void spdnet_nodepool_destroy(void *pool);
void *spdnet_nodepool_find(void *pool, const void *id, size_t len);
void *spdnet_nodepool_get(void *pool, int type);
void spdnet_nodepool_put(void *pool, void *snode);
void spdnet_nodepool_add(void *pool, void *snode);
void spdnet_nodepool_del(void *pool, void *snode);
int spdnet_nodepool_alive_count(void *pool);
int spdnet_nodepool_loop(void *pool, long timeout);

#endif
