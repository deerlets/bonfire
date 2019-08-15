#include "bonfire.h"
#include <assert.h>
#include <string.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

static void __bonfire_msg_init(struct bonfire_msg *bm)
{
	memset(bm, 0, sizeof(*bm));

	spdnet_msg_init(&bm->request);
	spdnet_msg_init(&bm->response);
	bm->user_arg = NULL;
	bm->user_data = NULL;

	bm->header = NULL;
	bm->header_len = 0;

	// srcid & dstid
	bm->srcid = NULL;
	bm->srcid_len = 0;
	bm->dstid = NULL;
	bm->dstid_len = 0;

	// snode which received the request
	bm->snode = NULL;

	// state
	bm->state = BM_RAW;
}

void bonfire_msg_set_request(struct bonfire_msg *bm, struct spdnet_msg *request)
{
	// copy request
	spdnet_msg_move(&bm->request, request);

	void *header = MSG_HEADER_DATA(&bm->request);
	size_t hdr_len = MSG_HEADER_SIZE(&bm->request);

	// init response
	// TODO: need performance optimization
	spdnet_frame_close(MSG_HEADER(&bm->response));
	spdnet_frame_init_size(MSG_HEADER(&bm->response),
	                       hdr_len + BONFIRE_RESPONSE_SUBFIX_LEN);
	memcpy(MSG_HEADER_DATA(&bm->response), header, hdr_len);
	memcpy((char *)MSG_HEADER_DATA(&bm->response) + hdr_len,
	       BONFIRE_RESPONSE_SUBFIX, BONFIRE_RESPONSE_SUBFIX_LEN);

	// request convenient
	bm->header = header;
	bm->header_len = hdr_len;
}

void bonfire_msg_init(struct bonfire_msg *bm, struct spdnet_msg *request)
{
	__bonfire_msg_init(bm);
	bonfire_msg_set_request(bm, request);
}

void bonfire_msg_init2(struct bonfire_msg *bm, const char *req_sockid,
                       const char *req_header, const char *req_content)
{
	__bonfire_msg_init(bm);

	struct spdnet_msg msg;
	SPDNET_MSG_INIT_DATA(&msg, req_sockid, req_header, req_content);
	bonfire_msg_set_request(bm, &msg);
	spdnet_msg_close(&msg);
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

void bonfire_msg_get_reqid(struct bonfire_msg *bm,
                           const void *sockid, size_t *len)
{
	sockid = bm->srcid;
	*len = bm->srcid_len;
}

void bonfire_msg_write_response(struct bonfire_msg *bm,
                                const void *data, int size)
{
	if (size == -1)
		size = strlen((const char *)data);

	spdnet_frame_close(MSG_CONTENT(&bm->response));
	spdnet_frame_init_size(MSG_CONTENT(&bm->response), size);
	memcpy(MSG_CONTENT_DATA(&bm->response), data, size);
}
