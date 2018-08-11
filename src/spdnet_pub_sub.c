#include "spdnet.h"

int spdnet_publish_init(struct spdnet_node *pub, const char *addr, void *ctx)
{
	if (spdnet_node_init(pub, SPDNET_PUB, ctx))
		return -1;

	if (spdnet_bind(pub, addr)) {
		spdnet_node_close(pub);
		return -1;
	}

	return 0;
}

int spdnet_publish_close(struct spdnet_node *pub)
{
	return spdnet_node_close(pub);
}

int spdnet_subscribe_init(struct spdnet_node *sub, const char *addr, void *ctx)
{
	if (spdnet_node_init(sub, SPDNET_SUB, ctx))
		return -1;

	if (spdnet_connect(sub, addr)) {
		spdnet_node_close(sub);
		return -1;
	}

	return 0;
}

int spdnet_subscribe_close(struct spdnet_node *sub)
{
	return spdnet_node_close(sub);
}

int spdnet_subscribe_set_filter(struct spdnet_node *sub,
                                const void *prefix, size_t len)
{
	return zmq_setsockopt(sub->socket, ZMQ_SUBSCRIBE, prefix, len);
}
