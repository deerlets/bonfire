#include <assert.h>
#include <string.h>
#include "bonfire-inl.h"

struct bmsg *bmsg_new()
{
	struct bmsg *bm = new struct bmsg;

	// request & response
	spdnet_msg_init(&bm->request);
	spdnet_msg_init(&bm->response);

	// bonfire cli
	bm->bf = NULL;

	// lifetime state
	bm->state = BM_RAW;

	// user data
	bm->user_data = NULL;

	return bm;
}

void bmsg_destroy(struct bmsg *bm)
{
	spdnet_msg_close(&bm->request);
	spdnet_msg_close(&bm->response);
	delete bm;
}

void bmsg_pending(struct bmsg *bm)
{
	assert(bm->state == BM_RAW);
	bm->state = BM_PENDING;
}

void bmsg_filtered(struct bmsg *bm)
{
	assert(bm->state <= BM_PENDING);
	bm->state = BM_FILTERED;
}

void bmsg_handled(struct bmsg *bm)
{
	assert(bm->state <= BM_PENDING);
	bm->state = BM_HANDLED;
}

struct bonfire *bmsg_get_bonfire(struct bmsg *bm)
{
	return bm->bf;
}

void *bmsg_get_user_data(struct bmsg *bm)
{
	return bm->user_data;
}

void bmsg_set_user_data(struct bmsg *bm, void *data)
{
	bm->user_data = data;
}

void bmsg_get_request_srcid(struct bmsg *bm, void **srcid, size_t *size)
{
	*srcid = MSG_SRCID_DATA(&bm->request);
	*size = MSG_SRCID_SIZE(&bm->request);
}

void bmsg_get_request_header(struct bmsg *bm, void **header, size_t *size)
{
	*header = MSG_HEADER_DATA(&bm->request);
	*size = MSG_HEADER_SIZE(&bm->request);
}

void bmsg_get_request_content(struct bmsg *bm, void **content, size_t *size)
{
	*content = MSG_CONTENT_DATA(&bm->request);
	*size = MSG_CONTENT_SIZE(&bm->request);
}

void bmsg_write_response(struct bmsg *bm, const char *data)
{
	bmsg_write_response_size(bm, data, strlen(data));
}

void bmsg_write_response_size(struct bmsg *bm, const void *data, size_t size)
{
	spdnet_frame_close(MSG_CONTENT(&bm->response));
	spdnet_frame_init_size(MSG_CONTENT(&bm->response), size);
	memcpy(MSG_CONTENT_DATA(&bm->response), data, size);
}
