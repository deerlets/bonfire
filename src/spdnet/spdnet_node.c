#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include "spdnet-inl.h"

int spdnet_node_init(struct spdnet_node *snode, struct spdnet_ctx *ctx, int type)
{
	memset(snode, 0, sizeof(*snode));

	snode->ctx = ctx;
	memset(snode->id, 0, sizeof(snode->id));
	snode->id_len = 0;

	snode->type = type;
	snode->alive_interval = 0;
	snode->alive_timeout = 0;

	snode->is_bind = 0;
	snode->is_connect = 0;
	memset(snode->bind_addr, 0, sizeof(snode->bind_addr));
	memset(snode->connect_addr, 0, sizeof(snode->connect_addr));
	snode->socket = zmq_socket(ctx->zmq_ctx, type);
	if (snode->socket == NULL)
		return -1;
	int linger = 1000;
	zmq_setsockopt(snode->socket, ZMQ_LINGER, &linger, sizeof(linger));

	snode->user_data = NULL;

	/* mainly used by spdnet_pool */
	snode->used = 0;
	snode->recvmsg_cb = NULL;
	snode->recvmsg_timeout = 0;
	INIT_LIST_HEAD(&snode->node);
	INIT_LIST_HEAD(&snode->pollin_node);
	INIT_LIST_HEAD(&snode->pollout_node);
	INIT_LIST_HEAD(&snode->pollerr_node);
	INIT_LIST_HEAD(&snode->recvmsg_timeout_node);

	return 0;
}

void spdnet_node_fini(struct spdnet_node *snode)
{
	assert(snode != NULL);
	assert(!snode->is_bind);
	assert(!snode->is_connect);
	assert(zmq_close(snode->socket) == 0);
}

struct spdnet_node *spdnet_node_new(struct spdnet_ctx *ctx, int type)
{
	struct spdnet_node *snode = spdnet_pool_get(ctx->pool, type);
	if (snode) return snode;

	if (type == SPDNET_DEALER)
		snode = spdnet_dealer_interface()->create(ctx);
	else if (type == SPDNET_PUB)
		snode = spdnet_pub_interface()->create(ctx);
	else if (type == SPDNET_SUB)
		snode = spdnet_sub_interface()->create(ctx);
	else if (type == SPDNET_ROUTER)
		snode = spdnet_router_interface()->create(ctx);
	else
		assert(0);

	spdnet_pool_add(ctx->pool, snode);
	return snode;
}

void spdnet_node_destroy(struct spdnet_node *snode)
{
	if (snode->used)
		spdnet_pool_put(snode->ctx->pool, snode);
	else
		snode->ifs->destroy(snode);
}

void *spdnet_get_socket(struct spdnet_node *snode)
{
	return snode->socket;
}

void spdnet_get_id(struct spdnet_node *snode, void *id, size_t *len)
{
	assert(id);
	assert(len);

	*len = snode->id_len;
	memcpy(id, snode->id, *len);
}

void spdnet_set_id(struct spdnet_node *snode, const void *id, size_t len)
{
	assert(id);
	assert(len <= SPDNET_SOCKID_SIZE);

	memcpy(snode->id, id, len);
	snode->id_len = len;

	assert(zmq_setsockopt(snode->socket, ZMQ_IDENTITY, id, len) == 0);
}

void spdnet_set_alive(struct spdnet_node *snode, int64_t alive)
{
	assert(snode->type == SPDNET_DEALER);

	if (alive < SPDNET_MIN_ALIVE_INTERVAL)
		snode->alive_interval = SPDNET_MIN_ALIVE_INTERVAL;
	else
		snode->alive_interval = alive;

	snode->alive_timeout = time(NULL) + snode->alive_interval;
}

void spdnet_set_filter(struct spdnet_node *snode, const void *prefix, size_t len)
{
	assert(snode->type == SPDNET_SUB);
	zmq_setsockopt(snode->socket, ZMQ_SUBSCRIBE, prefix, len);
}

void *spdnet_get_user_data(struct spdnet_node *snode)
{
	return snode->user_data;
}

void spdnet_set_user_data(struct spdnet_node *snode, void *user_data)
{
	snode->user_data = user_data;
}

int spdnet_bind(struct spdnet_node *snode, const char *addr)
{
	assert(snode->is_bind == 0);

	if (zmq_bind(snode->socket, addr))
		return -1;

	if (addr != snode->bind_addr)
		snprintf(snode->bind_addr, sizeof(snode->bind_addr), "%s", addr);
	snode->is_bind = 1;
	return 0;
}

void spdnet_unbind(struct spdnet_node *snode)
{
	assert(snode->is_bind == 1);

	assert(zmq_unbind(snode->socket, snode->bind_addr) == 0);
	snode->is_bind = 0;
}

int spdnet_connect(struct spdnet_node *snode, const char *addr)
{
	assert(snode->is_connect == 0);

	if (zmq_connect(snode->socket, addr))
		return -1;

	if (snode->type == SPDNET_DEALER) {
		if (spdnet_register(snode)) {
			zmq_disconnect(snode->socket, addr);
			return -1;
		}

		snode->alive_interval = SPDNET_ALIVE_INTERVAL;
		snode->alive_timeout = time(NULL) + SPDNET_ALIVE_INTERVAL;
	}

	if (addr != snode->connect_addr)
		snprintf(snode->connect_addr,
		         sizeof(snode->connect_addr),
		         "%s", addr);
	snode->is_connect = 1;
	return 0;
}

void spdnet_disconnect(struct spdnet_node *snode)
{
	assert(snode->is_connect == 1);

	if (snode->type == SPDNET_DEALER) {
		spdnet_unregister(snode);
		snode->alive_interval = 0;
		snode->alive_timeout = 0;
	}

	assert(zmq_disconnect(snode->socket, snode->connect_addr) == 0);
	snode->is_connect = 0;
}

int spdnet_register(struct spdnet_node *snode)
{
	int rc;

	struct spdnet_msg msg;
	spdnet_msg_init_data(&msg, SPDNET_SOCKID_NONE, SPDNET_SOCKID_NONE_LEN,
	                     SPDNET_REGISTER_MSG, SPDNET_REGISTER_MSG_LEN,
	                     NULL, 0);
	rc = spdnet_sendmsg(snode, &msg);
	spdnet_msg_close(&msg);

	if (rc == -1) return -1;
	return 0;
}

int spdnet_unregister(struct spdnet_node *snode)
{
	int rc;

	struct spdnet_msg msg;
	spdnet_msg_init_data(&msg, SPDNET_SOCKID_NONE, SPDNET_SOCKID_NONE_LEN,
	                     SPDNET_UNREGISTER_MSG, SPDNET_UNREGISTER_MSG_LEN,
	                     NULL, 0);
	rc = spdnet_sendmsg(snode, &msg);
	spdnet_msg_close(&msg);

	if (rc == -1) return -1;
	return 0;
}

int spdnet_expose(struct spdnet_node *snode)
{
	assert(snode->id_len);
	int rc;

	struct spdnet_msg msg;
	spdnet_msg_init_data(&msg, SPDNET_SOCKID_NONE, SPDNET_SOCKID_NONE_LEN,
	                     SPDNET_EXPOSE_MSG, SPDNET_EXPOSE_MSG_LEN,
	                     NULL, 0);
	rc = spdnet_sendmsg(snode, &msg);
	spdnet_msg_close(&msg);

	if (rc == -1) return -1;
	return 0;
}

int spdnet_alive(struct spdnet_node *snode)
{
	assert(snode->type == SPDNET_DEALER);
	int rc;

	struct spdnet_msg msg;
	spdnet_msg_init_data(&msg, SPDNET_SOCKID_NONE, SPDNET_SOCKID_NONE_LEN,
	                     SPDNET_ALIVE_MSG, SPDNET_ALIVE_MSG_LEN, NULL, 0);
	rc = spdnet_sendmsg(snode, &msg);
	spdnet_msg_close(&msg);

	if (rc == -1) return -1;
	return 0;
}

int spdnet_associate(struct spdnet_node *snode,
                     const char *addr, void *id, size_t *len)
{
	return snode->ifs->associate(snode, addr, id, len);
}

int spdnet_set_gateway(struct spdnet_node *snode, void *id, size_t len)
{
	return snode->ifs->set_gateway(snode, id, len);
}

int spdnet_recvmsg(struct spdnet_node *snode, struct spdnet_msg *msg)
{
	return snode->ifs->recvmsg(snode, msg);
}

int spdnet_recvmsg_timeout(struct spdnet_node *snode,
                           struct spdnet_msg *msg, int timeout)
{
	zmq_pollitem_t item;
	item.socket = spdnet_get_socket(snode);
	item.fd = 0;
	item.events = ZMQ_POLLIN;
	item.revents = 0;

	int rc = zmq_poll(&item, 1, timeout);
	if (rc == -1)
		return -1;
	else if (rc == 0)
		return SPDNET_ETIMEOUT;
	else if (rc == 1)
		return spdnet_recvmsg(snode, msg);
	else
		assert(0);
}

void spdnet_recvmsg_async(struct spdnet_node *snode, spdnet_recvmsg_cb cb,
                          void *arg, long timeout)
{
	assert(cb);

	snode->recvmsg_cb = cb;
	snode->recvmsg_arg = arg;
	if (timeout) snode->recvmsg_timeout = time(NULL) + timeout/1000;
	else snode->recvmsg_timeout = 0;
}

int spdnet_sendmsg(struct spdnet_node *snode, struct spdnet_msg *msg)
{
#ifdef HAVE_ZMQ_BUG
	usleep(10000);
#endif

	return snode->ifs->sendmsg(snode, msg);
}
