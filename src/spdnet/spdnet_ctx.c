#include <zmq.h>
#include "spdnet.h"

/*
 * spdnet_ctx
 */

void *spdnet_ctx_new(void)
{
	return zmq_ctx_new();
}

int spdnet_ctx_destroy(void *ctx)
{
	zmq_ctx_shutdown(ctx);
	return zmq_ctx_term(ctx);
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
