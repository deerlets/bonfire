#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "spdnet-inl.h"

struct spdnet_forwarder {
	void *pub;
	void *sub;
};

void *spdnet_forwarder_new(void *ctx)
{
	struct spdnet_forwarder *fwd = malloc(sizeof(*fwd));
	if (!fwd) return NULL;

	fwd->pub = spdnet_node_new(ctx, SPDNET_PUB);
	fwd->sub = spdnet_node_new(ctx, SPDNET_SUB);

	return fwd;
}

void spdnet_forwarder_destroy(void *__fwd)
{
	struct spdnet_forwarder *fwd = __fwd;
	spdnet_node_destroy(fwd->pub);
	spdnet_node_destroy(fwd->sub);
	free(fwd);
}

int
spdnet_forwarder_bind(void *__fwd, const char *pub_addr, const char *sub_addr)
{
	struct spdnet_forwarder *fwd = __fwd;

	if (spdnet_bind(fwd->pub, pub_addr))
		return -1;

	if (spdnet_bind(fwd->sub, sub_addr))
		return -1;

	spdnet_set_filter(fwd->sub, "", 0);

	return 0;
}

int spdnet_forwarder_loop(void *__fwd, long timeout)
{
	struct spdnet_forwarder *fwd = __fwd;
	int rc;

	zmq_pollitem_t items[] = {
		{ spdnet_get_socket(fwd->sub), 0, ZMQ_POLLIN, 0 },
	};

	rc = zmq_poll(items, 1, timeout);
	if (rc == 0 || rc == -1)
		return 0;

	if (items[0].revents & ZMQ_POLLIN) {
		struct spdnet_msg msg;
		spdnet_msg_init(&msg);
		spdnet_recvmsg(fwd->sub, &msg, 0);

#ifdef SPDNET_DEBUG
		char *topic = calloc(1, MSG_SOCKID_SIZE(&msg) + 1);
		char *content = calloc(1, MSG_CONTENT_SIZE(&msg) + 1);
		memcpy(topic, MSG_SOCKID_DATA(&msg), MSG_SOCKID_SIZE(&msg));
		memcpy(content, MSG_CONTENT_DATA(&msg), MSG_CONTENT_SIZE(&msg));
		fprintf(stderr, "[forwarder-%p]: topic=%s, content=%s\n",
		        fwd, topic, content);
		free(topic);
		free(content);
#endif

		spdnet_sendmsg(fwd->pub, &msg);
		spdnet_msg_close(&msg);
	}

	return 0;
}
