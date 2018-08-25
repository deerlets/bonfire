#include "service.h"

void servmsg_init(struct servmsg *sm, struct spdnet_msg *msg,
                  struct spdnet_node *snode)
{
	spdnet_msg_init(&sm->request);
	spdnet_msg_move(&sm->request, msg);

	void *sockid = MSG_SOCKID_DATA(&sm->request);
	size_t id_len = MSG_SOCKID_SIZE(&sm->request);
	void *header = MSG_HEADER_DATA(&sm->request);
	size_t hdr_len = MSG_HEADER_SIZE(&sm->request);

	// TODO: need performance optimization
	spdnet_msg_init_data(&sm->response, sockid, id_len, NULL, 0, NULL, 0);
	zmq_msg_close(MSG_HEADER(&sm->response));
	zmq_msg_init_size(MSG_HEADER(&sm->response), hdr_len + 6);
	memcpy(MSG_HEADER_DATA(&sm->response), header, hdr_len);
	memcpy((char *)MSG_HEADER_DATA(&sm->response) + hdr_len, "_reply", 6);

	sm->snode = snode;

	if (!snode || snode->type == SPDNET_SUB) {
		sm->src = NULL;
		sm->src_len = 0;
		sm->dest = sockid;
		sm->dest_len = id_len;
	} else {
		sm->src = sockid;
		sm->src_len = id_len;
		sm->dest = snode->id;
		sm->dest_len = strlen(snode->id);
	}

	sm->header = header;
	sm->header_len = hdr_len;

	sm->user_data = NULL;
	sm->rc = 0;
	sm->errmsg = NULL;
	sm->state = SM_RAW_INTERRUPTIBLE;

	INIT_LIST_HEAD(&sm->node);
}

void servmsg_init_uninterruptible(struct servmsg *sm, struct spdnet_msg *msg,
                                  struct spdnet_node *snode)
{
	servmsg_init(sm, msg, snode);
	sm->state = SM_RAW_UNINTERRUPTIBLE;
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

void servmsg_handled(struct servmsg *sm, int rc)
{
	assert(sm->state <= SM_PENDING);
	sm->state = SM_HANDLED;
	sm->rc = rc;
}

int servmsg_error(struct servmsg *sm, int err, const char *errmsg)
{
	sm->rc = err;
	sm->errmsg = errmsg;
	return err;
}

const char *servmsg_reqid(struct servmsg *sm)
{
	return spdnet_msg_gets(&sm->request, "name");
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
