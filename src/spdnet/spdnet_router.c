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
	struct spdnet_ctx *ctx;
	struct spdnet_node *snode;
	struct list_head routing_table;

	int nr_msg_routerd;
	int nr_msg_dropped;
};

static int
spdnet_peer_remote(struct spdnet_ctx *ctx, const char *addr, void *id, size_t *len)
{
	int rc = 0;
	char buf[32] = "peer";
	struct spdnet_msg msg;
	struct spdnet_node *snode;

	SPDNET_MSG_INIT_DATA(&msg, buf, "hello", "world");
	snode = spdnet_node_new(ctx, SPDNET_NODE);
	spdnet_set_id(snode, buf, strlen(buf));

	rc = spdnet_connect(snode, addr);
	if (rc == -1) goto finally;

	rc = spdnet_sendmsg(snode, &msg);
	if (rc == -1) goto finally;

#if HAVE_ZMQ_BUG
	zmq_sleep(1);
#endif

#if defined(__WIN32)
	rc = spdnet_recvmsg(snode, &msg, ZMQ_DONTWAIT);
	if (rc == -1) goto finally;
	const char *value = zmq_msg_gets(MSG_SOCKID(&msg), "Identity");
	assert(value);
	strcpy(id, value);
	*len = strlen(value);
#else
	void *socket = spdnet_get_socket(snode);
	// sockid
	rc = z_recv_more(socket, MSG_SOCKID(&msg), 0);
	if (rc == -1) goto finally;
	rc = z_recv_more(socket, MSG_SOCKID(&msg), 0);
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

	// meta, use content to get meta
	rc = z_recv_more(socket, MSG_CONTENT(&msg), 0);
	if (rc == -1) goto finally;
	*len = MSG_CONTENT_SIZE(&msg);
	memcpy(id, MSG_CONTENT_DATA(&msg), *len);
	rc = z_recv_not_more(socket, MSG_CONTENT(&msg), 0);
	if (rc == -1) {
		z_clear(socket);
		goto finally;
	}
#endif

finally:
	spdnet_msg_close(&msg);
	spdnet_node_destroy(snode);
	return rc;
}

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
		    pos->nexthop_type == SPDNET_NODE &&
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

static void routing_msg(struct spdnet_router *router,
                        struct spdnet_routing_item *dst_routing,
                        zmq_msg_t *srcid, zmq_msg_t *dstid,
                        zmq_msg_t *header, zmq_msg_t *content,
                        zmq_msg_t *meta)
{
	int rc;
	void *socket = spdnet_get_socket(router->snode);

	rc = zmq_send(socket, dst_routing->nexthop_id,
	              dst_routing->nexthop_len, ZMQ_SNDMORE);
	assert(rc != -1);

	rc = zmq_send(socket, &router->snode->type, 1, ZMQ_SNDMORE);
	assert(rc != -1);
	rc = zmq_msg_send(srcid, socket, ZMQ_SNDMORE);
	assert(rc != -1);

	if (dst_routing->nexthop_type == SPDNET_ROUTER) {
		rc = zmq_send(socket, "", 0, ZMQ_SNDMORE);
		assert(rc != -1);
		rc = zmq_msg_send(dstid, socket, ZMQ_SNDMORE);
		assert(rc != -1);
	}

	rc = zmq_send(socket, "", 0, ZMQ_SNDMORE);
	assert(rc != -1);
	rc = zmq_msg_send(header, socket, ZMQ_SNDMORE);
	assert(rc != -1);

	rc = zmq_send(socket, "", 0, ZMQ_SNDMORE);
	assert(rc != -1);
	rc = zmq_msg_send(content, socket, ZMQ_SNDMORE);
	assert(rc != -1);

	rc = zmq_send(socket, router->snode->id,
	              router->snode->id_len, ZMQ_SNDMORE);
	assert(rc != -1);
	rc = zmq_msg_send(meta, socket, 0);
	assert(rc != -1);
}

static int handle_msg_from_router(struct spdnet_router *router, zmq_msg_t *rid)
{
	int rc, err;
	void *socket = spdnet_get_socket(router->snode);
	zmq_msg_t srcid, dstid, header, content, meta;
	zmq_msg_init(&srcid);
	zmq_msg_init(&dstid);
	zmq_msg_init(&header);
	zmq_msg_init(&content);
	zmq_msg_init(&meta);

	// recv routered msg
	rc = z_recv_more(socket, &srcid, 0);
	if (rc == -1) goto finally;

	rc = z_recv_more(socket, &dstid, 0);
	if (rc == -1) goto finally;
	rc = z_recv_more(socket, &dstid, 0);
	if (rc == -1) goto finally;

	rc = z_recv_more(socket, &header, 0);
	if (rc == -1) goto finally;
	rc = z_recv_more(socket, &header, 0);
	if (rc == -1) goto finally;

	rc = z_recv_more(socket, &content, 0);
	if (rc == -1) goto finally;
	rc = z_recv_more(socket, &content, 0);
	if (rc == -1) goto finally;

	rc = z_recv_more(socket, &meta, 0);
	if (rc == -1) goto finally;
	rc = z_recv_not_more(socket, &meta, 0);
	if (rc == -1) {
		z_clear(socket);
		goto finally;
	}

#ifdef SPDNET_DEBUG
	char *__rid = calloc(1, zmq_msg_size(rid) + 1);
	char *__srcid = calloc(1, zmq_msg_size(&srcid) + 1);
	char *__dstid = calloc(1, zmq_msg_size(&dstid) + 1);
	char *__header = calloc(1, zmq_msg_size(&header) + 1);
	char *__content = calloc(1, zmq_msg_size(&content) + 1);
	memcpy(__rid, zmq_msg_data(rid), zmq_msg_size(rid));
	memcpy(__srcid, zmq_msg_data(&srcid), zmq_msg_size(&srcid));
	memcpy(__dstid, zmq_msg_data(&dstid), zmq_msg_size(&dstid));
	memcpy(__header, zmq_msg_data(&header), zmq_msg_size(&header));
	memcpy(__content, zmq_msg_data(&content), zmq_msg_size(&content));
	fprintf(stderr, "[%s]: rid=%s, srcid=%s, "
	        "dstid=%s, header=%s, content=%s\n",
	        router->snode->id, __rid, __srcid,
	        __dstid, __header, __content);
	free(__rid);
	free(__srcid);
	free(__dstid);
	free(__header);
	free(__content);
#endif

	// save router routing
	struct spdnet_routing_item *router_routing =
		spdnet_find_routing_item_ex(router, rid);
	// handle unregister msg
	if (memcmp(zmq_msg_data(&header), SPDNET_UNREGISTER_MSG,
	           SPDNET_UNREGISTER_MSG_LEN) == 0) {
		if (router_routing) {
			list_del(&router_routing->node);
			free(router_routing);
		}
		rc = 0;
		goto finally;
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

	// filter register msg, after router routing, before src routing
	if (memcmp(zmq_msg_data(&header), SPDNET_REGISTER_MSG,
	           SPDNET_REGISTER_MSG_LEN) == 0) {
		rc = 0;
		goto finally;
	}

	// save src routing
	struct spdnet_routing_item *src_routing =
		spdnet_find_routing_item_ex(router, &srcid);
	if (!src_routing) {
		src_routing = malloc(sizeof(*src_routing));
		INIT_SPDNET_ROUTING_ITEM(src_routing,
		                         zmq_msg_data(&srcid),
		                         zmq_msg_size(&srcid),
		                         zmq_msg_data(rid),
		                         zmq_msg_size(rid),
		                         SPDNET_ROUTER);
		list_add(&src_routing->node, &router->routing_table);
	}

	// find dst routing
	struct spdnet_routing_item *dst_routing =
		spdnet_find_routing_item_ex(router, &dstid);
	if (!dst_routing) {
		dst_routing = spdnet_find_routing_item(
			router, SPDNET_ROUTER_DEFAULT_GATEWAY,
			strlen(SPDNET_ROUTER_DEFAULT_GATEWAY));
		if (!dst_routing) {
			errno = SPDNET_EROUTING;
			rc = -1;
			goto finally;
		}
	}

	// start routering msg
	routing_msg(router, dst_routing, &srcid, &dstid,
	            &header, &content, &meta);

	rc = 0;
finally:
	err = errno;
	zmq_msg_close(&srcid);
	zmq_msg_close(&dstid);
	zmq_msg_close(&header);
	zmq_msg_close(&content);
	zmq_msg_close(&meta);
	errno = err;
	return rc;
}

static int handle_msg_from_node(struct spdnet_router *router, zmq_msg_t *srcid)
{
	int rc, err;
	void *socket = spdnet_get_socket(router->snode);
	zmq_msg_t dstid, header, content, meta;
	zmq_msg_init(&dstid);
	zmq_msg_init(&header);
	zmq_msg_init(&content);
	zmq_msg_init(&meta);

	// recv routered msg
	rc = z_recv_more(socket, &dstid, 0);
	if (rc == -1) goto finally;

	rc = z_recv_more(socket, &header, 0);
	if (rc == -1) goto finally;
	rc = z_recv_more(socket, &header, 0);
	if (rc == -1) goto finally;

	rc = z_recv_more(socket, &content, 0);
	if (rc == -1) goto finally;
	rc = z_recv_more(socket, &content, 0);
	if (rc == -1) goto finally;

	rc = z_recv_more(socket, &meta, 0);
	if (rc == -1) goto finally;
	rc = z_recv_not_more(socket, &meta, 0);
	if (rc == -1) {
		z_clear(socket);
		goto finally;
	}

#ifdef SPDNET_DEBUG
	char *__srcid = calloc(1, zmq_msg_size(srcid) + 1);
	char *__dstid = calloc(1, zmq_msg_size(&dstid) + 1);
	char *__header = calloc(1, zmq_msg_size(&header) + 1);
	char *__content = calloc(1, zmq_msg_size(&content) + 1);
	memcpy(__srcid, zmq_msg_data(srcid), zmq_msg_size(srcid));
	memcpy(__dstid, zmq_msg_data(&dstid), zmq_msg_size(&dstid));
	memcpy(__header, zmq_msg_data(&header), zmq_msg_size(&header));
	memcpy(__content, zmq_msg_data(&content), zmq_msg_size(&content));
	fprintf(stderr, "[%s]: srcid=%s, dstid=%s, header=%s, content=%s\n",
	        router->snode->id, __srcid, __dstid, __header, __content);
	free(__srcid);
	free(__dstid);
	free(__header);
	free(__content);
#endif

	// save src routing
	struct spdnet_routing_item *src_routing =
		spdnet_find_routing_item_ex(router, srcid);
	// handle unregister msg
	if (memcmp(zmq_msg_data(&header), SPDNET_UNREGISTER_MSG,
	           SPDNET_UNREGISTER_MSG_LEN) == 0) {
		if (src_routing) {
			list_del(&src_routing->node);
			free(src_routing);
		}
		rc = 0;
		goto finally;
	}
	if (!src_routing) {
		src_routing = malloc(sizeof(*src_routing));
		INIT_SPDNET_ROUTING_ITEM(src_routing,
		                         zmq_msg_data(srcid),
		                         zmq_msg_size(srcid),
		                         zmq_msg_data(srcid),
		                         zmq_msg_size(srcid),
		                         SPDNET_NODE);
		list_add(&src_routing->node, &router->routing_table);
	}

	// after src routing, before dst routing,
	// filter register & alive msg but expose msg
	if (memcmp(zmq_msg_data(&header), SPDNET_REGISTER_MSG,
	           SPDNET_REGISTER_MSG_LEN) == 0 ||
	    memcmp(zmq_msg_data(&header), SPDNET_ALIVE_MSG,
	           SPDNET_ALIVE_MSG_LEN) == 0) {
		rc = 0;
		goto finally;
	}

	// find dst routing
	struct spdnet_routing_item *dst_routing =
		spdnet_find_routing_item_ex(router, &dstid);
	if (!dst_routing) {
		dst_routing = spdnet_find_routing_item(
			router, SPDNET_ROUTER_DEFAULT_GATEWAY,
			strlen(SPDNET_ROUTER_DEFAULT_GATEWAY));
		if (!dst_routing) {
			errno = SPDNET_EROUTING;
			rc = -1;
			goto finally;
		}
	}

	// start routering msg
	routing_msg(router, dst_routing, srcid, &dstid,
	            &header, &content, &meta);

	rc = 0;
finally:
	err = errno;
	zmq_msg_close(&dstid);
	zmq_msg_close(&header);
	zmq_msg_close(&content);
	zmq_msg_close(&meta);
	errno = err;
	return rc;
}

static int on_pollin(struct spdnet_router *router)
{
	int rc, err;
	void *socket = spdnet_get_socket(router->snode);
	zmq_msg_t srcid, delimiter;
	zmq_msg_init(&srcid);
	zmq_msg_init(&delimiter);

	rc = z_recv_more(socket, &srcid, 0);
	if (rc == -1) goto finally;

	rc = z_recv_more(socket, &delimiter, 0);
	if (rc == -1) goto finally;

#if defined(__WIN32)
	// zmq_msg_gets always fails with srcid
	const char *socket_type = zmq_msg_gets(&delimiter, "Socket-Type");
	if (!socket_type) {
		z_clear(socket);
		errno = SPDNET_ESOCKETTYPE;
		rc = -1;
		goto finally;
	}

	if (!strcmp(socket_type, "ROUTER"))
		rc = handle_msg_from_router(router, &srcid);
	else if (!strcmp(socket_type, "DEALER"))
		rc = handle_msg_from_node(router, &srcid);
	else {
		z_clear(socket);
		errno = SPDNET_ESOCKETTYPE;
		rc = -1;
		goto finally;
	}
#else
	if (zmq_msg_size(&delimiter) != 1) {
		z_clear(socket);
		errno = SPDNET_ESOCKETTYPE;
		rc = -1;
		goto finally;
	}
	uint8_t *type = zmq_msg_data(&delimiter);
	if (*type == SPDNET_ROUTER)
		rc = handle_msg_from_router(router, &srcid);
	else if (*type == SPDNET_NODE)
		rc = handle_msg_from_node(router, &srcid);
	else {
		z_clear(socket);
		errno = SPDNET_ESOCKETTYPE;
		rc = -1;
		goto finally;
	}
#endif

finally:
	err = errno;
	zmq_msg_close(&srcid);
	zmq_msg_close(&delimiter);
	errno = err;
	return rc;
}

struct spdnet_router *spdnet_router_new(struct spdnet_ctx *ctx, const char *id)
{
	struct spdnet_router *router = malloc(sizeof(*router));
	if (!router) return NULL;

	memset(router, 0, sizeof(*router));
	router->ctx = ctx;

	router->snode = spdnet_node_new(ctx, ZMQ_ROUTER);
	if (!router->snode) {
		free(router);
		return NULL;
	}

	if (id && *id) {
		assert(strlen(id) <= SPDNET_SOCKID_SIZE);
		spdnet_set_id(router->snode, id, strlen(id));
	}

	INIT_LIST_HEAD(&router->routing_table);

	router->nr_msg_routerd = 0;
	router->nr_msg_dropped = 0;

	return router;
}

void spdnet_router_destroy(struct spdnet_router *router)
{
	struct spdnet_routing_item *pos, *n;
	list_for_each_entry_safe(pos, n, &router->routing_table, node) {
		list_del(&pos->node);
		free(pos);
	}

	spdnet_node_destroy(router->snode);
	free(router);
}

int spdnet_router_bind(struct spdnet_router *router, const char *addr)
{
	return spdnet_bind(router->snode, addr);
}

int spdnet_router_associate(struct spdnet_router *router,
                            const char *addr, void *id, size_t *len)
{
	char remote_id[SPDNET_SOCKID_SIZE];
	size_t remote_len;

	if (spdnet_peer_remote(router->ctx, addr, remote_id, &remote_len) == -1)
		return -1;
	if (id && len) {
		memcpy(id, remote_id, remote_len);
		*len = remote_len;
	}

	if (spdnet_connect(router->snode, addr) == -1)
		return -1;

#if HAVE_ZMQ_BUG
	zmq_sleep(1);
#endif

	// rid
	spdnet_send(router->snode, remote_id, remote_len, ZMQ_SNDMORE);

	// srcid
	spdnet_send(router->snode, &router->snode->type, 1, ZMQ_SNDMORE);
	spdnet_send(router->snode, SPDNET_SOCKID_NONE,
	            SPDNET_SOCKID_NONE_LEN, ZMQ_SNDMORE);

	// dstid
	spdnet_send(router->snode, "", 0, ZMQ_SNDMORE);
	spdnet_send(router->snode, SPDNET_SOCKID_NONE,
	            SPDNET_SOCKID_NONE_LEN, ZMQ_SNDMORE);

	// header
	spdnet_send(router->snode, "", 0, ZMQ_SNDMORE);
	spdnet_send(router->snode, SPDNET_REGISTER_MSG,
	            SPDNET_REGISTER_MSG_LEN, ZMQ_SNDMORE);

	// content
	spdnet_send(router->snode, "", 0, ZMQ_SNDMORE);
	spdnet_send(router->snode, "", 0, ZMQ_SNDMORE);

	// meta
	spdnet_send(router->snode, "", 0, ZMQ_SNDMORE);
	spdnet_send(router->snode, "", 0, 0);

	struct spdnet_routing_item *item = malloc(sizeof(*item));
	INIT_SPDNET_ROUTING_ITEM(item, remote_id, remote_len,
	                         remote_id, remote_len, SPDNET_ROUTER);
	list_add(&item->node, &router->routing_table);

	return 0;
}

int spdnet_router_set_gateway(struct spdnet_router *router, void *id, size_t len)
{
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

int spdnet_router_msg_routerd(struct spdnet_router *router)
{
	return router->nr_msg_routerd;
}

int spdnet_router_msg_dropped(struct spdnet_router *router)
{
	return router->nr_msg_dropped;
}

int spdnet_router_loop(struct spdnet_router *router, long timeout)
{
	int rc;

	zmq_pollitem_t items[] = {
		{ spdnet_get_socket(router->snode), 0, ZMQ_POLLIN, 0 },
	};

	rc = zmq_poll(items, 1, timeout);
	if (rc == 0 || rc == -1)
		return 0;

	if (items[0].revents & ZMQ_POLLIN) {
		rc = on_pollin(router);
		if (rc == 0)
			router->nr_msg_routerd++;
		else
			router->nr_msg_dropped++;
	}

	return 0;
}
