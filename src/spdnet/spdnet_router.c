#include <errno.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "spdnet-inl.h"

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
	struct spdnet_node snode;
	struct list_head routing_table;
};

static struct spdnet_routing_item *
spdnet_find_routing_item(struct spdnet_router *router, const void *id, size_t len)
{
	struct spdnet_routing_item *pos, *n;
	list_for_each_entry_safe(pos, n, &router->routing_table, node) {
		if (pos->len == len && !memcmp(pos->id, id, len)) {
			pos->atime = time(NULL);
			return pos;
		}

		if (pos->atime + SPDNET_ROUTING_ITEM_STALL < time(NULL) &&
		    pos->nexthop_type == SPDNET_DEALER &&
		    pos->len == pos->nexthop_len &&
		    memcmp(pos->id, pos->nexthop_id, pos->len) == 0) {
			list_del(&pos->node);
			free(pos);
		}
	}
	return NULL;
}

static inline struct spdnet_routing_item *
spdnet_find_routing_item_ex(struct spdnet_router *router, zmq_msg_t *id)
{
	return spdnet_find_routing_item(router, zmq_msg_data(id),
	                                zmq_msg_size(id));
}

void spdnet_builtin_router_recvmsg_cb(struct spdnet_node *snode,
                                      struct spdnet_msg *msg,
                                      void *arg, int flag)
{
	if (flag) {
		fprintf(stderr, "[%s]: flag => %d\n", __func__, flag);
		return;
	}
	assert(msg);

#ifdef SPDNET_DEBUG
	char *__srcid = calloc(1, MSG_SRCID_SIZE(msg) + 1);
	char *__dstid = calloc(1, MSG_DSTID_SIZE(msg) + 1);
	char *__header = calloc(1, MSG_HEADER_SIZE(msg) + 1);
	char *__content = calloc(1, MSG_CONTENT_SIZE(msg) + 1);
	memcpy(__srcid, MSG_SRCID_DATA(msg), MSG_SRCID_SIZE(msg));
	memcpy(__dstid, MSG_DSTID_DATA(msg), MSG_DSTID_SIZE(msg));
	memcpy(__header, MSG_HEADER_DATA(msg), MSG_HEADER_SIZE(msg));
	memcpy(__content, MSG_CONTENT_DATA(msg), MSG_CONTENT_SIZE(msg));
	fprintf(stderr, "[%s]: srcid=%s, dstid=%s, header=%s, content=%s\n",
	        snode->id, __srcid, __dstid, __header, __content);
	free(__srcid);
	free(__dstid);
	free(__header);
	free(__content);
#endif

	if (memcmp(MSG_DSTID_DATA(msg), SPDNET_SOCKID_NONE,
	           strlen(SPDNET_SOCKID_NONE)) != 0)
		spdnet_sendmsg(snode, msg);

	spdnet_recvmsg_async(snode, spdnet_builtin_router_recvmsg_cb, arg, 0);
}

static struct spdnet_node *spdnet_router_create(struct spdnet_ctx *ctx)
{
	struct spdnet_router *router = malloc(sizeof(*router));
	if (!router) return NULL;
	memset(router, 0, sizeof(*router));

	if (spdnet_node_init(&router->snode, ctx, SPDNET_ROUTER)) {
		free(router);
		return NULL;
	}
	router->snode.ifs = spdnet_router_interface();
	INIT_LIST_HEAD(&router->routing_table);

	return &router->snode;
}

static void spdnet_router_destroy(struct spdnet_node *snode)
{
	struct spdnet_router *router =
		container_of(snode, struct spdnet_router, snode);

	struct spdnet_routing_item *pos, *n;
	list_for_each_entry_safe(pos, n, &router->routing_table, node) {
		list_del(&pos->node);
		free(pos);
	}

	spdnet_node_fini(snode);
	free(router);
}

static int handle_msg_from_router(struct spdnet_node *snode,
                                  struct spdnet_msg *msg,
                                  zmq_msg_t *rid)
{
	struct spdnet_router *router =
		container_of(snode, struct spdnet_router, snode);
	void *socket = spdnet_get_socket(snode);

	// recv routered msg
	if (z_recv_more(socket, MSG_SRCID(msg), 0))
		return -1;

	if (z_recv_more(socket, MSG_DSTID(msg), 0))
		return -1;
	if (z_recv_more(socket, MSG_DSTID(msg), 0))
		return -1;

	if (z_recv_more(socket, MSG_HEADER(msg), 0))
		return -1;
	if (z_recv_more(socket, MSG_HEADER(msg), 0))
		return -1;

	if (z_recv_more(socket, MSG_CONTENT(msg), 0))
		return -1;
	if (z_recv_more(socket, MSG_CONTENT(msg), 0))
		return -1;

	if (z_recv_more(socket, MSG_META(msg), 0))
		return -1;
	if (z_recv_not_more(socket, MSG_META(msg), 0)) {
		z_clear(socket);
		return -1;
	}

	// save router routing
	struct spdnet_routing_item *router_routing =
		spdnet_find_routing_item_ex(router, rid);
	// handle unregister msg
	if (memcmp(MSG_HEADER_DATA(msg), SPDNET_UNREGISTER_MSG,
	           strlen(SPDNET_UNREGISTER_MSG)) == 0) {
		if (router_routing) {
			list_del(&router_routing->node);
			free(router_routing);
		}
		return 0;
	}
	if (!router_routing) {
		router_routing = malloc(sizeof(*router_routing));
		INIT_SPDNET_ROUTING_ITEM(router_routing,
		                         zmq_msg_data(rid),
		                         zmq_msg_size(rid),
		                         zmq_msg_data(rid),
		                         zmq_msg_size(rid),
		                         SPDNET_ROUTER);
		list_add(&router_routing->node, &router->routing_table);
	}

	return 0;
}

static int handle_msg_from_dealer(struct spdnet_node *snode,
                                  struct spdnet_msg *msg,
                                  zmq_msg_t *srcid)
{
	struct spdnet_router *router =
		container_of(snode, struct spdnet_router, snode);
	void *socket = spdnet_get_socket(snode);

	// recv routered msg
	if (zmq_msg_copy(MSG_SRCID(msg), srcid))
		return -1;

	if (z_recv_more(socket, MSG_DSTID(msg), 0))
		return -1;

	if (z_recv_more(socket, MSG_HEADER(msg), 0))
		return -1;
	if (z_recv_more(socket, MSG_HEADER(msg), 0))
		return -1;

	if (z_recv_more(socket, MSG_CONTENT(msg), 0))
		return -1;
	if (z_recv_more(socket, MSG_CONTENT(msg), 0))
		return -1;

	if (z_recv_more(socket, MSG_META(msg), 0))
		return -1;
	if (z_recv_not_more(socket, MSG_META(msg), 0)) {
		z_clear(socket);
		return -1;
	}

	// save src routing
	struct spdnet_routing_item *src_routing =
		spdnet_find_routing_item_ex(router, srcid);
	// handle unregister msg
	if (memcmp(MSG_HEADER_DATA(msg), SPDNET_UNREGISTER_MSG,
	           strlen(SPDNET_UNREGISTER_MSG)) == 0) {
		if (src_routing) {
			list_del(&src_routing->node);
			free(src_routing);
		}
		return 0;
	}
	if (!src_routing) {
		src_routing = malloc(sizeof(*src_routing));
		INIT_SPDNET_ROUTING_ITEM(src_routing,
		                         zmq_msg_data(srcid),
		                         zmq_msg_size(srcid),
		                         zmq_msg_data(srcid),
		                         zmq_msg_size(srcid),
		                         SPDNET_DEALER);
		list_add(&src_routing->node, &router->routing_table);
	}

	return 0;
}

static int
spdnet_router_recvmsg(struct spdnet_node *snode, struct spdnet_msg *msg)
{
	int rc, err;
	void *socket = spdnet_get_socket(snode);
	zmq_msg_t srcid, node_type;
	zmq_msg_init(&srcid);
	zmq_msg_init(&node_type);

	rc = z_recv_more(socket, &srcid, 0);
	if (rc == -1) goto finally;

	rc = z_recv_more(socket, &node_type, 0);
	if (rc == -1) goto finally;

	if (zmq_msg_size(&node_type) != 1) {
		z_clear(socket);
		errno = SPDNET_ESOCKETTYPE;
		rc = -1;
		goto finally;
	}
	uint8_t *type = zmq_msg_data(&node_type);
	if (*type == SPDNET_ROUTER)
		rc = handle_msg_from_router(snode, msg, &srcid);
	else if (*type == SPDNET_DEALER)
		rc = handle_msg_from_dealer(snode, msg, &srcid);
	else {
		z_clear(socket);
		errno = SPDNET_ESOCKETTYPE;
		rc = -1;
		goto finally;
	}

finally:
	err = errno;
	zmq_msg_close(&srcid);
	zmq_msg_close(&node_type);
	errno = err;
	return rc;
}

static int
spdnet_router_sendmsg(struct spdnet_node *snode, struct spdnet_msg *msg)
{
	struct spdnet_router *router =
		container_of(snode, struct spdnet_router, snode);
	void *socket = spdnet_get_socket(snode);

	// find dst routing
	char *dstid = MSG_DSTID_DATA(msg);
	size_t dstid_size = MSG_DSTID_SIZE(msg);
	if (dstid_size > strlen(snode->id) + 1 &&
	    memcmp(snode->id, dstid, strlen(snode->id)) == 0 &&
	    *(dstid + strlen(snode->id)) == SPDNET_ID_DELIMITER) {
		dstid += strlen(snode->id) + 1;
		dstid_size -= (strlen(snode->id) + 1);
	}
	char *p = memchr(dstid, SPDNET_ID_DELIMITER, dstid_size);
	if (p) dstid_size = p - dstid;
	struct spdnet_routing_item *dst_routing =
		spdnet_find_routing_item(router, dstid, dstid_size);
	if (!dst_routing) {
		dst_routing = spdnet_find_routing_item(
			router, SPDNET_ROUTER_DEFAULT_GATEWAY,
			strlen(SPDNET_ROUTER_DEFAULT_GATEWAY));
		if (!dst_routing) {
			errno = SPDNET_EROUTING;
			return -1;
		}
	}

	// routing
	int rc;
	rc = zmq_send(socket, dst_routing->nexthop_id,
	              dst_routing->nexthop_len, ZMQ_SNDMORE);
	assert(rc != -1);

	rc = zmq_send(socket, &snode->type, 1, ZMQ_SNDMORE);
	assert(rc != -1);
	if (dst_routing->nexthop_type == SPDNET_ROUTER) {
		// insert self-rid as prefix
		zmq_msg_t srcid_msg;
		zmq_msg_init_size(&srcid_msg, strlen(snode->id) +
		                  MSG_SRCID_SIZE(msg) + 1);
		char *tmp = zmq_msg_data(&srcid_msg);
		memcpy(tmp, snode->id, strlen(snode->id));
		*(tmp + strlen(snode->id)) = SPDNET_ID_DELIMITER;
		memcpy(tmp + strlen(snode->id) + 1, MSG_SRCID_DATA(msg),
		       MSG_SRCID_SIZE(msg));
		rc = zmq_msg_send(&srcid_msg, socket, ZMQ_SNDMORE);
		assert(rc != -1);
		zmq_msg_close(&srcid_msg);
	} else {
		rc = zmq_msg_send(MSG_SRCID(msg), socket, ZMQ_SNDMORE);
		assert(rc != -1);
	}

	if (dst_routing->nexthop_type == SPDNET_ROUTER) {
		rc = zmq_send(socket, "", 0, ZMQ_SNDMORE);
		assert(rc != -1);
		// remove self-rid
		zmq_msg_t dstid_msg;
		size_t dstid_msg_size = (char *)MSG_DSTID_DATA(msg) +
			MSG_DSTID_SIZE(msg) - dstid;
		zmq_msg_init_size(&dstid_msg, dstid_msg_size);
		memcpy(zmq_msg_data(&dstid_msg), dstid, dstid_msg_size);
		rc = zmq_msg_send(&dstid_msg, socket, ZMQ_SNDMORE);
		zmq_msg_close(&dstid_msg);
		assert(rc != -1);
	}

	rc = zmq_send(socket, "", 0, ZMQ_SNDMORE);
	assert(rc != -1);
	rc = zmq_msg_send(MSG_HEADER(msg), socket, ZMQ_SNDMORE);
	assert(rc != -1);

	rc = zmq_send(socket, "", 0, ZMQ_SNDMORE);
	assert(rc != -1);
	rc = zmq_msg_send(MSG_CONTENT(msg), socket, ZMQ_SNDMORE);
	assert(rc != -1);

	rc = zmq_send(socket, snode->id, strlen(snode->id), ZMQ_SNDMORE);
	assert(rc != -1);
	rc = zmq_msg_send(MSG_META(msg), socket, 0);
	assert(rc != -1);

	return 0;
}

static int
peer_remote(struct spdnet_ctx *ctx, const char *addr, void *id, size_t *len)
{
	int rc = 0;
	struct spdnet_msg msg;
	struct spdnet_node *snode;

	SPDNET_MSG_INIT_DATA(&msg, "peer", "hello", "world");
	snode = spdnet_node_new(ctx, SPDNET_DEALER);
	spdnet_set_id(snode, "peer");

	rc = spdnet_connect(snode, addr);
	if (rc == -1) goto finally;

	rc = spdnet_sendmsg(snode, &msg);
	if (rc == -1) goto finally;

#if HAVE_ZMQ_BUG
	zmq_sleep(1);
#endif

	void *socket = spdnet_get_socket(snode);
	// dstid
	rc = z_recv_more(socket, MSG_DSTID(&msg), 0);
	if (rc == -1) goto finally;
	rc = z_recv_more(socket, MSG_DSTID(&msg), 0);
	if (rc == -1) goto finally;

	// header
	rc = z_recv_more(socket, MSG_HEADER(&msg), 0);
	if (rc == -1) goto finally;
	rc = z_recv_more(socket, MSG_HEADER(&msg), 0);
	if (rc == -1) goto finally;

	// content
	rc = z_recv_more(socket, MSG_CONTENT(&msg), 0);
	if (rc == -1) goto finally;
	rc = z_recv_more(socket, MSG_CONTENT(&msg), 0);
	if (rc == -1) goto finally;

	// meta
	rc = z_recv_more(socket, MSG_META(&msg), 0);
	if (rc == -1) goto finally;
	*len = MSG_META_SIZE(&msg);
	memcpy(id, MSG_META_DATA(&msg), *len);
	rc = z_recv_not_more(socket, MSG_META(&msg), 0);
	if (rc == -1) {
		z_clear(socket);
		goto finally;
	}

finally:
	spdnet_msg_close(&msg);
	spdnet_node_destroy(snode);
	return rc;
}

static int spdnet_router_associate(struct spdnet_node *snode,
                                   const char *addr,
                                   void *id, size_t *len)
{
	struct spdnet_router *router =
		container_of(snode, struct spdnet_router, snode);

	char remote_id[SPDNET_SOCKID_SIZE];
	size_t remote_len;

	if (peer_remote(snode->ctx, addr, remote_id, &remote_len) == -1)
		return -1;
	if (id && len) {
		memcpy(id, remote_id, remote_len);
		*len = remote_len;
	}

	if (spdnet_connect(snode, addr) == -1)
		return -1;

#if HAVE_ZMQ_BUG
	zmq_sleep(1);
#endif

	// rid
	zmq_send(snode, remote_id, remote_len, ZMQ_SNDMORE);

	// srcid
	zmq_send(snode, &snode->type, 1, ZMQ_SNDMORE);
	zmq_send(snode, SPDNET_SOCKID_NONE,
	         strlen(SPDNET_SOCKID_NONE), ZMQ_SNDMORE);

	// dstid
	zmq_send(snode, "", 0, ZMQ_SNDMORE);
	zmq_send(snode, SPDNET_SOCKID_NONE,
	         strlen(SPDNET_SOCKID_NONE), ZMQ_SNDMORE);

	// header
	zmq_send(snode, "", 0, ZMQ_SNDMORE);
	zmq_send(snode, SPDNET_REGISTER_MSG,
	         strlen(SPDNET_REGISTER_MSG), ZMQ_SNDMORE);

	// content
	zmq_send(snode, "", 0, ZMQ_SNDMORE);
	zmq_send(snode, "", 0, ZMQ_SNDMORE);

	// meta
	zmq_send(snode, "", 0, ZMQ_SNDMORE);
	zmq_send(snode, "", 0, 0);

	struct spdnet_routing_item *item = malloc(sizeof(*item));
	INIT_SPDNET_ROUTING_ITEM(item, remote_id, remote_len,
	                         remote_id, remote_len, SPDNET_ROUTER);
	list_add(&item->node, &router->routing_table);

	return 0;
}

static int
spdnet_router_set_gateway(struct spdnet_node *snode, void *id, size_t len)
{
	struct spdnet_router *router =
		container_of(snode, struct spdnet_router, snode);

	const char *gw = SPDNET_ROUTER_DEFAULT_GATEWAY;

	struct spdnet_routing_item *item =
		spdnet_find_routing_item(router, gw, strlen(gw));

	if (!item) {
		item = malloc(sizeof(*item));
		INIT_SPDNET_ROUTING_ITEM(item, gw, strlen(gw),
		                         id, len, SPDNET_ROUTER);
		list_add(&item->node, &router->routing_table);
	} else
		INIT_SPDNET_ROUTING_ITEM(item, gw, strlen(gw),
		                         id, len, SPDNET_ROUTER);

	return 0;
}

static struct spdnet_interface router_if = {
	.create = spdnet_router_create,
	.destroy = spdnet_router_destroy,
	.recvmsg = spdnet_router_recvmsg,
	.sendmsg = spdnet_router_sendmsg,
	.associate = spdnet_router_associate,
	.set_gateway = spdnet_router_set_gateway,
};

struct spdnet_interface *spdnet_router_interface()
{
	return &router_if;
}
