#ifndef __SPDNET_SPDNET_INTERNAL_H
#define __SPDNET_SPDNET_INTERNAL_H

#include <pthread.h> // pthread_mutex_t
#include <zmq.h>
#include "list.h"

typedef zmq_msg_t spdnet_frame_t;
#include "spdnet.h"

void z_clear(void *s);
int z_recv_more(void *s, spdnet_frame_t *frame, int flags);
int z_recv_not_more(void *s, spdnet_frame_t *frame, int flags);

struct spdnet_node {
	char id[SPDNET_SOCKID_SIZE];
	size_t id_len;

	int type;
	int64_t alive_interval;
	int64_t alive_timeout;

	char addr[SPDNET_ADDRESS_SIZE];
	void *socket;

	void *user_data;

	/* mainly used by spdnet_nodepool */
	spdnet_recvmsg_cb recvmsg_cb;
	void *recvmsg_arg;
	int64_t recvmsg_timeout;
	int count;
	int eof;
	struct list_head node;
	struct list_head pollin_node;
	struct list_head pollout_node;
	struct list_head pollerr_node;
	struct list_head recvmsg_timeout_node;
};

struct spdnet_nodepool {
	void *ctx;
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

struct spdnet_routing_item {
	char id[SPDNET_SOCKID_SIZE];
	size_t len;

	char nexthop_id[SPDNET_SOCKID_SIZE];
	size_t nexthop_len;
	int nexthop_type;

	int64_t atime;

	struct list_head node;
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
	struct spdnet_node *snode;
	struct list_head routing_table;

	int nr_msg_routerd;
	int nr_msg_dropped;
};

#endif
