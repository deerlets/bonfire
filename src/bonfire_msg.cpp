#include <assert.h>
#include <string.h>
#include <nlohmann/json.hpp>
#include "bonfire-internal.h"

using json = nlohmann::json;

void bonfire_msg_init(struct bonfire_msg *bm)
{
	memset(bm, 0, sizeof(*bm));

	// request & response
	spdnet_msg_init(&bm->request);
	spdnet_msg_init(&bm->response);

	// user arg
	bm->user_arg = NULL;

	// lifetime state
	bm->state = BM_RAW;

	// snode which received the request
	bm->snode = NULL;
}

void bonfire_msg_close(struct bonfire_msg *bm)
{
	spdnet_msg_close(&bm->request);
	spdnet_msg_close(&bm->response);
}

void bonfire_msg_pending(struct bonfire_msg *bm)
{
	assert(bm->state == BM_RAW);
	bm->state = BM_PENDING;
}

void bonfire_msg_filtered(struct bonfire_msg *bm)
{
	assert(bm->state <= BM_PENDING);
	bm->state = BM_FILTERED;
}

void bonfire_msg_handled(struct bonfire_msg *bm)
{
	assert(bm->state <= BM_PENDING);
	bm->state = BM_HANDLED;
}

void *bonfire_msg_get_user_arg(struct bonfire_msg *bm)
{
	return bm->user_arg;
}

void bonfire_msg_set_user_arg(struct bonfire_msg *bm, void *arg)
{
	bm->user_arg = arg;
}

void bonfire_msg_get_request(struct bonfire_msg *bm, void **data, size_t *size)
{
	*data = MSG_CONTENT_DATA(&bm->request);
	*size = MSG_CONTENT_SIZE(&bm->request);
}

void bonfire_msg_write_response(struct bonfire_msg *bm, const char *data)
{
	bonfire_msg_write_response_size(bm, data, strlen(data));
}

void bonfire_msg_write_response_size(struct bonfire_msg *bm,
                                     const void *data,
                                     size_t size)
{
	spdnet_frame_close(MSG_CONTENT(&bm->response));
	spdnet_frame_init_size(MSG_CONTENT(&bm->response), size);
	memcpy(MSG_CONTENT_DATA(&bm->response), data, size);
}
