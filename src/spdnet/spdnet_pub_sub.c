#include "spdnet-internal.h"

void *spdnet_publish_new(const char *addr, void *ctx)
{
	void *pub = spdnet_node_new(SPDNET_PUB, ctx);
	if (!pub) return NULL;

	if (spdnet_bind(pub, addr)) {
		spdnet_node_destroy(pub);
		return NULL;
	}

	return pub;
}

int spdnet_publish_destroy(void *pub)
{
	return spdnet_node_destroy(pub);
}

void *spdnet_subscribe_new(const char *addr, void *ctx)
{
	void *sub = spdnet_node_new(SPDNET_SUB, ctx);
	if (!sub) return NULL;

	if (spdnet_connect(sub, addr)) {
		spdnet_node_destroy(sub);
		return NULL;
	}

	return sub;
}

int spdnet_subscribe_destroy(void *sub)
{
	return spdnet_node_destroy(sub);
}

int spdnet_subscribe_set_filter(void *__sub, const void *prefix, size_t len)
{
	struct spdnet_node *sub = __sub;
	return zmq_setsockopt(sub->socket, ZMQ_SUBSCRIBE, prefix, len);
}
