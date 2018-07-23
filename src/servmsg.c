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

	sm->user_data = NULL;
	sm->rc = 0;
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
