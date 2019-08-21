#ifndef __BONFIRE_BONFIRE_INL_H
#define __BONFIRE_BONFIRE_INL_H

#include <spdnet.h>
#include "bonfire.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BONFIRE_RESPONSE_SUBFIX "#reply"

enum bmsg_lifetime_state {
	// raw
	BM_RAW = 0,

	// intermediate
	BM_PENDING = 0x10,

	// result
	BM_FILTERED = 0x20,
	BM_HANDLED,
};

struct bmsg {
	// sockid of request should be dstid after init before using
	struct spdnet_msg request;

	// sockid of response should be srcid after init before using
	struct spdnet_msg response;

	// bonfire cli
	struct bonfire *bf;

	// lifetime state
	int state;

	// bonfire never touch user_data
	void *user_data;
};

struct bmsg *bmsg_new();
void bmsg_destroy(struct bmsg *bm);

#ifdef __cplusplus
}
#endif
#endif
