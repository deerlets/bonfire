#ifndef __BONFIRE_BONFIRE_INTERNAL_H
#define __BONFIRE_BONFIRE_INTERNAL_H

#include <spdnet.h>
#include "bonfire.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BONFIRE_RESPONSE_SUBFIX "#reply"

enum bonfire_msg_lifetime_state {
	// raw
	BM_RAW = 0,

	// intermediate
	BM_PENDING = 0x10,

	// result
	BM_FILTERED = 0x20,
	BM_HANDLED,
};

struct bonfire_msg {
	// sockid of request should be dstid after init before using
	struct spdnet_msg request;

	// sockid of response should be srcid after init before using
	struct spdnet_msg response;

	// bonfire'll init it with msg_arg but never touch it any more
	void *user_arg;

	// bonfire never touch user_data
	void *user_data;

	/* used by bonfire only */

	// snode which received the request
	void *snode;

	// lifetime state
	int state;
};

void bonfire_msg_init(struct bonfire_msg *bm);
void bonfire_msg_close(struct bonfire_msg *bm);

#ifdef __cplusplus
}
#endif
#endif
