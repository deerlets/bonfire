#include "spdnet.h"
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <zmq.h>

int spdnet_node_init(struct spdnet_node *snode, int type, void *ctx)
{
	memset(snode, 0, sizeof(*snode));

	memset(snode->id, 0, sizeof(snode->id));
	snode->id_len = 0;

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
	memset(snode, 0, sizeof(*snode));

	memset(snode->id, 0, sizeof(snode->id));
	snode->id_len = 0;
	zmq_getsockopt(socket, ZMQ_IDENTITY, snode->id, &snode->id_len);

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

void spdnet_setalive(struct spdnet_node *snode, time_t alive)
{
	assert(snode->type == SPDNET_NODE);

	if (alive < SPDNET_MIN_ALIVE_INTERVAL)
		snode->alive_interval = SPDNET_MIN_ALIVE_INTERVAL;
	else
		snode->alive_interval = alive;

	snode->alive_timeout = time(NULL) + snode->alive_interval;
}

int spdnet_bind(struct spdnet_node *snode, const char *addr)
{
	snprintf(snode->addr, sizeof(snode->addr), "%s", addr);
	return zmq_bind(snode->socket, addr);
}

int spdnet_connect(struct spdnet_node *snode, const char *addr)
{
	int rc;

	if (addr != snode->addr)
		snprintf(snode->addr, sizeof(snode->addr), "%s", addr);
	rc = zmq_connect(snode->socket, addr);

	if (rc == 0 && snode->type == SPDNET_NODE)
		rc = spdnet_register(snode);

	return rc;
}

int spdnet_disconnect(struct spdnet_node *snode)
{
	if (snode->type == SPDNET_NODE)
		spdnet_unregister(snode);
	if (strlen(snode->addr))
		return zmq_disconnect(snode->socket, snode->addr);
	return 0;
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
	assert(snode->id_len);
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
	if (snode->type == SPDNET_NODE) {
		rc = z_recv_more(snode->socket, MSG_SOCKID(msg), flags);
		if (rc == -1) return -1;
	}
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
	zmq_msg_t meta_msg;
	zmq_msg_init(&meta_msg);
	rc = z_recv_more(snode->socket, &meta_msg, flags);
	if (rc == -1) {
		zmq_msg_close(&meta_msg);
		return -1;
	}
	rc = z_recv_not_more(snode->socket, &meta_msg, flags);
	if (rc == -1) {
		z_clear(snode->socket);
		zmq_msg_close(&meta_msg);
		return -1;
	}

	if (msg->__meta) free(msg->__meta);
	msg->__meta = malloc(zmq_msg_size(&meta_msg));
	memcpy(msg->__meta, zmq_msg_data(&meta_msg), zmq_msg_size(&meta_msg));
	assert(zmq_msg_size(&meta_msg) == sizeof(*(msg->__meta)));
	zmq_msg_close(&meta_msg);

	return 0;
}

void spdnet_recvmsg_async(struct spdnet_node *snode,
                          spdnet_recvmsg_cb recvmsg_cb,
                          void *recvmsg_arg, long timeout)
{
	snode->recvmsg_cb = recvmsg_cb;
	snode->recvmsg_arg = recvmsg_arg;
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
	if (snode->type == SPDNET_NODE) {
		rc = zmq_send(snode->socket, &snode->type, 1,
		              ZMQ_SNDMORE | ZMQ_DONTWAIT);
		if (rc == -1) return -1;
	}
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

	spdnet_meta_t meta;
	meta.node_type = snode->type;
	meta.ttl = 10;

	zmq_msg_t meta_msg;
	zmq_msg_init_size(&meta_msg, sizeof(meta));
	memcpy(zmq_msg_data(&meta_msg), &meta, sizeof(meta));
	rc = zmq_msg_send(&meta_msg, snode->socket, 0);
	zmq_msg_close(&meta_msg);
	if (rc == -1) return -1;

	return 0;
}
