#include "service.h"

void servmsg_init(struct servmsg *sm, struct spdnet_msg *msg,
                  struct spdnet_node *snode)
{
	spdnet_msg_init(&sm->request);
	spdnet_msg_move(&sm->request, msg);

	void *sockid = zmq_msg_data(MSG_SOCKID(&sm->request));
	size_t id_len = zmq_msg_size(MSG_SOCKID(&sm->request));
	void *header = zmq_msg_data(MSG_HEADER(&sm->request));
	size_t hdr_len = zmq_msg_size(MSG_HEADER(&sm->request));

	// TODO: need performance optimization
	spdnet_msg_init_data(&sm->response, sockid, id_len, NULL, 0, NULL, 0);
	zmq_msg_close(MSG_HEADER(&sm->response));
	zmq_msg_init_size(MSG_HEADER(&sm->response), hdr_len + 6);
	memcpy(zmq_msg_data(MSG_HEADER(&sm->response)), header, hdr_len);
	memcpy((char *)zmq_msg_data(MSG_HEADER(&sm->response)) + hdr_len,
	       "_reply", 6);

	sm->snode = snode;

	if (!snode || snode->type == SPDNET_SUB) {
		sm->src = NULL;
		sm->src_len = 0;
		sm->dest = zmq_msg_data(MSG_SOCKID(&sm->request));
		sm->dest_len = zmq_msg_size(MSG_SOCKID(&sm->request));
	} else {
		sm->src = zmq_msg_data(MSG_SOCKID(&sm->request));
		sm->src_len = zmq_msg_size(MSG_SOCKID(&sm->request));
		sm->dest = snode->id;
		sm->dest_len = strlen(snode->id);
	}

	sm->rc = 0;
}

void servmsg_close(struct servmsg *sm)
{
	spdnet_msg_close(&sm->request);
	spdnet_msg_close(&sm->response);
}
