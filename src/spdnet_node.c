#include "spdnet.h"
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <zmq.h>
#include <libbson-1.0/bson.h>

int spdnet_node_init(struct spdnet_node *snode, int type, void *ctx)
{
	memset(snode->id, 0, sizeof(snode->id));
	snode->id_len = 0;

	memset(snode->name, 0, sizeof(snode->name));
	snode->type = type;
	snode->alive_interval = 0;
	snode->alive_timeout = 0;

	memset(snode->addr, 0, sizeof(snode->addr));
	snode->socket = zmq_socket(ctx, type);
	if (snode->socket == NULL)
		return -1;
	int linger = 1000;
	zmq_setsockopt(snode->socket, ZMQ_LINGER, &linger, sizeof(linger));

	snode->user_data = NULL;

	/* mainly used by spdnet_nodepool */
	snode->recvmsg_cb = NULL;
	snode->recvmsg_timeout = 0;
	snode->count = 1;
	snode->eof = 0;
	INIT_LIST_HEAD(&snode->node);
	INIT_LIST_HEAD(&snode->pollin_node);
	INIT_LIST_HEAD(&snode->pollout_node);
	INIT_LIST_HEAD(&snode->pollerr_node);
	INIT_LIST_HEAD(&snode->recvmsg_timeout_node);
	return 0;
}

int spdnet_node_init_socket(struct spdnet_node *snode, int type, void *socket)
{
	memset(snode->id, 0, sizeof(snode->id));
	snode->id_len = 0;
	zmq_getsockopt(socket, ZMQ_IDENTITY, snode->id, &snode->id_len);

	memset(snode->name, 0, sizeof(snode->name));
	snode->type = type;
	snode->alive_interval = 0;
	snode->alive_timeout = 0;

	memset(snode->addr, 0, sizeof(snode->addr));
	snode->socket = socket;
	int linger = 1000;
	zmq_setsockopt(snode->socket, ZMQ_LINGER, &linger, sizeof(linger));

	snode->user_data = NULL;

	/* mainly used by spdnet_nodepool */
	snode->recvmsg_cb = NULL;
	snode->recvmsg_timeout = 0;
	snode->count = 1;
	snode->eof = 0;
	INIT_LIST_HEAD(&snode->node);
	INIT_LIST_HEAD(&snode->pollin_node);
	INIT_LIST_HEAD(&snode->pollout_node);
	INIT_LIST_HEAD(&snode->pollerr_node);
	INIT_LIST_HEAD(&snode->recvmsg_timeout_node);
	return 0;
}

int spdnet_node_close(struct spdnet_node *snode)
{
	assert(snode != NULL);
	if (zmq_close(snode->socket) == -1)
		return -1;
	return 0;
}

void *spdnet_node_get_socket(struct spdnet_node *snode)
{
	return snode->socket;
}

int spdnet_setid(struct spdnet_node *snode, const void *id, size_t len)
{
	assert(id);
	assert(len <= SPDNET_SOCKID_SIZE);

	memcpy(snode->id, id, len);
	snode->id_len = len;

	return zmq_setsockopt(snode->socket, ZMQ_IDENTITY, id, len);
}

void spdnet_setname(struct spdnet_node *snode, const char *name)
{
	assert(strlen(name) < SPDNET_NAME_SIZE);
	strcpy(snode->name, name);
}

void spdnet_setalive(struct spdnet_node *snode, time_t alive)
{
	assert(snode->type == SPDNET_NODE);

	if (alive < SPDNET_MIN_ALIVE_INTERVAL)
		snode->alive_interval = SPDNET_MIN_ALIVE_INTERVAL;
	else
		snode->alive_interval = alive;

	snode->alive_timeout = time(NULL) + snode->alive_interval;
}

const char *spdnet_getname(struct spdnet_node *snode)
{
	return snode->name;
}

int spdnet_bind(struct spdnet_node *snode, const char *addr)
{
	snprintf(snode->addr, sizeof(snode->addr), "%s", addr);
	return zmq_bind(snode->socket, addr);
}

int spdnet_connect(struct spdnet_node *snode, const char *addr)
{
	snprintf(snode->addr, sizeof(snode->addr), "%s", addr);
	return zmq_connect(snode->socket, addr);
}

int spdnet_disconnect(struct spdnet_node *snode)
{
	if (strlen(snode->addr))
		return zmq_disconnect(snode->socket, snode->addr);
	return 0;
}

int spdnet_register(struct spdnet_node *snode)
{
	assert(snode->id_len);
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

int spdnet_alive(struct spdnet_node *snode)
{
	assert(snode->type == SPDNET_NODE);
	assert(snode->id_len);
	int rc;
	struct spdnet_msg msg;

	spdnet_msg_init_data(&msg, SPDNET_SOCKID_NONE, SPDNET_SOCKID_NONE_LEN,
	                     SPDNET_ALIVE_MSG, SPDNET_ALIVE_MSG_LEN, NULL, 0);
	rc = spdnet_sendmsg(snode, &msg);
	spdnet_msg_close(&msg);

	if (rc == -1) return -1;
	return 0;
}

int spdnet_recv(struct spdnet_node *snode, void *buf, size_t size, int flags)
{
	return zmq_recv(snode->socket, buf, size, flags);
}

int spdnet_send(struct spdnet_node *snode,
                const void *buf, size_t size, int flags)
{
	return zmq_send(snode->socket, buf, size, flags);
}

int spdnet_recvmsg(struct spdnet_node *snode, struct spdnet_msg *msg, int flags)
{
	int rc = 0;

	// sockid
	rc = z_recv_more(snode->socket, MSG_SOCKID(msg), flags);
	if (rc == -1) return -1;
	rc = z_recv_more(snode->socket, MSG_SOCKID(msg), flags);
	if (rc == -1) return -1;

	// header
	rc = z_recv_more(snode->socket, MSG_HEADER(msg), flags);
	if (rc == -1) return -1;
	rc = z_recv_more(snode->socket, MSG_HEADER(msg), flags);
	if (rc == -1) return -1;

	// content
	rc = z_recv_more(snode->socket, MSG_CONTENT(msg), flags);
	if (rc == -1) return -1;
	rc = z_recv_more(snode->socket, MSG_CONTENT(msg), flags);
	if (rc == -1) return -1;

	// meta
	zmq_msg_t meta;
	zmq_msg_init(&meta);
	rc = z_recv_more(snode->socket, &meta, flags);
	if (rc == -1) {
		zmq_msg_close(&meta);
		return -1;
	}
	rc = z_recv_not_more(snode->socket, &meta, flags);
	if (rc == -1) {
		zmq_msg_close(&meta);
		return -1;
	}

	bson_t *b;
	bson_iter_t iter;
	if ((b = bson_new_from_data(zmq_msg_data(&meta), zmq_msg_size(&meta))) &&
	    bson_iter_init(&iter, b)) {
		if (bson_iter_find(&iter, "name") &&
		    BSON_ITER_HOLDS_UTF8(&iter)) {
			snprintf(msg->__meta.name, SPDNET_NAME_SIZE, "%s",
			         bson_iter_utf8(&iter, NULL));
		}

		if (bson_iter_find(&iter, "node-type") &&
		    BSON_ITER_HOLDS_INT32(&iter))
			msg->__meta.node_type = bson_iter_int32(&iter);

		if (bson_iter_find(&iter, "ttl") &&
		    BSON_ITER_HOLDS_INT32(&iter))
			msg->__meta.ttl = bson_iter_int32(&iter);

		bson_destroy(b);
	}

	zmq_msg_close(&meta);
	return 0;
}

void spdnet_recvmsg_async(struct spdnet_node *snode,
                          spdnet_recvmsg_cb recvmsg_cb, long timeout)
{
	snode->recvmsg_cb = recvmsg_cb;
	if (timeout) snode->recvmsg_timeout = time(NULL) + timeout/1000;
	else snode->recvmsg_timeout = 0;
}

int spdnet_sendmsg(struct spdnet_node *snode, struct spdnet_msg *msg)
{
#ifdef HAVE_ZMQ_BUG
	usleep(10000);
#endif

	int rc = 0;

	// sockid
	rc = zmq_send(snode->socket, &snode->type, 1, ZMQ_SNDMORE);
	if (rc == -1) return -1;
	rc = zmq_msg_send(MSG_SOCKID(msg), snode->socket, ZMQ_SNDMORE);
	if (rc == -1) return -1;

	// header
	rc = zmq_send(snode->socket, "", 0, ZMQ_SNDMORE);
	if (rc == -1) return -1;
	rc = zmq_msg_send(MSG_HEADER(msg), snode->socket, ZMQ_SNDMORE);
	if (rc == -1) return -1;

	// content
	rc = zmq_send(snode->socket, "", 0, ZMQ_SNDMORE);
	if (rc == -1) return -1;
	rc = zmq_msg_send(MSG_CONTENT(msg), snode->socket, ZMQ_SNDMORE);
	if (rc == -1) return -1;

	// meta
	rc = zmq_send(snode->socket, "", 0, ZMQ_SNDMORE);
	if (rc == -1) return -1;

	bson_t *b = bson_new();
	bson_append_utf8(b, "name", -1, snode->name, -1);
	bson_append_int32(b, "node-type", -1, snode->type);
	bson_append_int32(b, "ttl", -1, 10);

	zmq_msg_t meta;
	zmq_msg_init_size(&meta, b->len);
	memcpy(zmq_msg_data(&meta), bson_get_data(b), b->len);
	rc = zmq_msg_send(&meta, snode->socket, 0);
	zmq_msg_close(&meta);
	bson_destroy(b);
	if (rc == -1) return -1;

	return 0;
}
