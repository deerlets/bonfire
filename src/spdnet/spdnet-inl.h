#ifndef __SPDNET_SPDNET_INL_H
#define __SPDNET_SPDNET_INL_H

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

#endif
