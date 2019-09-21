#include <stdlib.h>
#include <zmq.h>
#include <pthread.h>
#include "spdnet-inl.h"

/*
 * spdnet_ctx
 */

struct spdnet_ctx *spdnet_ctx_new(void)
{
	struct spdnet_ctx *ctx = malloc(sizeof(*ctx));
	if (!ctx) return NULL;
	ctx->zmq_ctx = zmq_ctx_new();
	ctx->pool = spdnet_pool_new(ctx, 20);
	return ctx;
}

void spdnet_ctx_destroy(struct spdnet_ctx *ctx)
{
	spdnet_pool_destroy(ctx->pool);
	zmq_ctx_shutdown(ctx->zmq_ctx);
	zmq_ctx_term(ctx->zmq_ctx);
	free(ctx);
}

int spdnet_loop(struct spdnet_ctx *ctx, long timeout)
{
	return spdnet_pool_loop(ctx->pool, timeout);
}

/*
 * zhelper
 */

void z_clear(void *s)
{
	zmq_msg_t msg;

	zmq_msg_init(&msg);

	do {
		if (zmq_msg_recv(&msg, s, ZMQ_DONTWAIT) == -1)
			break;
	} while (zmq_msg_more(&msg));

	zmq_msg_close(&msg);
}

int z_recv_more(void *s, zmq_msg_t *msg, int flags)
{
	if (zmq_msg_recv(msg, s, flags) == -1) {
		errno = SPDNET_EIO;
		return -1;
	}

	if (!zmq_msg_more(msg)) {
		errno = SPDNET_EPROTOCOL;
		return -1;
	}

	return 0;
}

int z_recv_not_more(void *s, zmq_msg_t *msg, int flags)
{
	if (zmq_msg_recv(msg, s, flags) == -1) {
		errno = SPDNET_EIO;
		return -1;
	}

	if (zmq_msg_more(msg)) {
		errno = SPDNET_EPROTOCOL;
		return -1;
	}

	return 0;
}
