#include "service.h"
#include <assert.h>
#include <string.h>

static void __servmsg_init(struct servmsg *sm)
{
	memset(sm, 0, sizeof(*sm));
	spdnet_msg_init(&sm->request);
	spdnet_msg_init(&sm->response);

	sm->header = NULL;
	sm->header_len = 0;
	sm->area = NULL;
	sm->area_len = 0;
	sm->service = NULL;
	sm->service_len = 0;

	// srcid & dstid
	sm->srcid = NULL;
	sm->srcid_len = 0;
	sm->dstid = NULL;
	sm->dstid_len = 0;

	// snode which received the request
	sm->snode = NULL;

	// ...
	sm->state = SM_RAW_INTERRUPTIBLE;
	sm->err = SERVICE_EOK;
	sm->errmsg = service_strerror(SERVICE_EOK);
	INIT_LIST_HEAD(&sm->node);
	sm->user_data = NULL;
}

void servmsg_set_request(struct servmsg *sm, struct spdnet_msg *request)
{
	// copy request
	spdnet_msg_move(&sm->request, request);

	void *header = MSG_HEADER_DATA(&sm->request);
	size_t hdr_len = MSG_HEADER_SIZE(&sm->request);

	// init response
	// TODO: need performance optimization
	zmq_msg_close(MSG_HEADER(&sm->response));
	zmq_msg_init_size(MSG_HEADER(&sm->response),
	                  hdr_len + RESPONSE_SUBFIX_LEN);
	memcpy(MSG_HEADER_DATA(&sm->response), header, hdr_len);
	memcpy((char *)MSG_HEADER_DATA(&sm->response) + hdr_len,
	       RESPONSE_SUBFIX, RESPONSE_SUBFIX_LEN);

	// request convenient
	sm->header = header;
	sm->header_len = hdr_len;
	sm->area = header;
	sm->area_len = hdr_len;
	sm->service = NULL;
	sm->service_len = 0;

	char *p;
	p = strstr(header, SERVAREA_DELIMITER);
	if (p) {
		sm->area_len = p - (char *)header;
		p += strlen(SERVAREA_DELIMITER);
		sm->service = p;
		p = strchr(p, SERVICE_DELIMITER);
		if (p) {
			sm->service_len = p - (char *)sm->service;
		} else {
			sm->service_len = (char *)header + hdr_len
				- (char *)sm->service;
		}
	}
}

void servmsg_init(struct servmsg *sm, struct spdnet_msg *request)
{
	__servmsg_init(sm);
	servmsg_set_request(sm, request);
}

void servmsg_init2(struct servmsg *sm, const char *req_sockid,
                   const char *req_header, const char *req_content)
{
	__servmsg_init(sm);

	struct spdnet_msg msg;
	SPDNET_MSG_INIT_DATA(&msg, req_sockid, req_header, req_content);
	servmsg_set_request(sm, &msg);
	spdnet_msg_close(&msg);
}

void servmsg_close(struct servmsg *sm)
{
	spdnet_msg_close(&sm->request);
	spdnet_msg_close(&sm->response);
}

int servmsg_interruptible(struct servmsg *sm)
{
	assert(sm->state < SM_PENDING);

	if (sm->state == SM_RAW_INTERRUPTIBLE)
		return 1;
	return 0;
}

void servmsg_pending(struct servmsg *sm)
{
	assert(sm->state == SM_RAW_INTERRUPTIBLE);
	sm->state = SM_PENDING;
}

void servmsg_filtered(struct servmsg *sm)
{
	assert(sm->state <= SM_PENDING && sm->state != SM_RAW_UNINTERRUPTIBLE);
	sm->state = SM_FILTERED;
}

void servmsg_timeout(struct servmsg *sm)
{
	assert(sm->state <= SM_PENDING);
	sm->state = SM_TIMEOUT;
}

void servmsg_handled(struct servmsg *sm)
{
	assert(sm->state <= SM_PENDING);
	sm->state = SM_HANDLED;
}

void servmsg_set_error(struct servmsg *sm, int err, const char *errmsg)
{
	sm->err = err;
	sm->errmsg = errmsg;
}

const char *servmsg_reqid(struct servmsg *sm)
{
	return MSG_SOCKID_DATA(&sm->request);
}

int servmsg_respcnt_reset_data(struct servmsg *sm, const void *data, int size)
{
	if (size == -1)
		size = strlen((const char *)data);

	zmq_msg_close(MSG_CONTENT(&sm->response));
	zmq_msg_init_size(MSG_CONTENT(&sm->response), size);
	memcpy(MSG_CONTENT_DATA(&sm->response), data, size);
	return 0;
}
