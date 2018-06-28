#include "service.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "timer.h"

struct servhub *default_servhub(void)
{
	static struct servhub servhub;
	return &servhub;
}

#define SERVICE_STRERROR_GEN(name, msg) case SERVICE_ ## name: return msg;
const char *service_strerror(int err) {
	switch (err) {
		SERVICE_ERRNO_MAP(SERVICE_STRERROR_GEN)
	}
	return "unknown errno";
}
#undef SERVICE_STRERROR_GEN

static int on_blackhole(struct servmsg *sm)
{
	return SERVICE_ENOSERV;
}

static struct service services[] = {
	SERVICE_INIT_PRIVATE("blackhole", on_blackhole, NULL),
	SERVICE_INIT(NULL, NULL, NULL),
};

static struct servarea *
find_servarea(struct servhub *hub, const char *name, size_t len)
{
	struct servarea *pos;
	list_for_each_entry(pos, &hub->servareas, node) {
		if (len == strlen(pos->name) && !memcmp(pos->name, name, len))
			return pos;
	}
	return NULL;
}

static void finish_msg(struct servhub *hub, struct servmsg *sm)
{
	const char *cnt = zmq_msg_data(MSG_CONTENT(&sm->response));
	int cnt_len = zmq_msg_size(MSG_CONTENT(&sm->response));

	if (!cnt || !cnt_len) {
		cnt = "null";
		cnt_len = strlen(cnt);
	}

	// FIXME: if 64 is large enough
	char *buf = malloc(64 + cnt_len);
	int nr = snprintf(buf, 64 + cnt_len,
	                  "{\"errno\": %d, \"errmsg\": \"%s\", \"result\": ",
	                  -sm->rc, service_strerror(sm->rc));
	memcpy(buf + nr, cnt, cnt_len);
	buf[nr + cnt_len] = '}';
	buf[nr + cnt_len + 1] = '\0';

	zmq_msg_close(MSG_CONTENT(&sm->response));
	zmq_msg_init_size(MSG_CONTENT(&sm->response), strlen(buf));
	memcpy(zmq_msg_data(MSG_CONTENT(&sm->response)), buf, strlen(buf));
	free(buf);
}

static void handle_msg(struct servhub *hub, struct servmsg *sm)
{
	mutex_lock(&hub->servareas_lock);
	struct servarea *sa;
	if (!(sa = find_servarea(hub, sm->reqserv, sm->reqserv_len))) {
		mutex_unlock(&hub->servareas_lock);
		sm->rc = SERVICE_ENOSERV;
		return;
	}

	service_handler_func_t fn;
	fn = servarea_find_handler(sa, servmsg_reqhdr_data(sm),
	                           servmsg_reqhdr_size(sm));
	mutex_unlock(&hub->servareas_lock);
	if (!fn) {
		sm->rc = SERVICE_ENOREQ;
		return;
	}

	sm->rc = fn(sm);
}

static int filter_msg(struct servhub *hub, struct spdnet_msg *msg,
                      struct spdnet_node *snode)
{
	void *sockid = zmq_msg_data(MSG_SOCKID(msg));
	size_t id_len = zmq_msg_size(MSG_SOCKID(msg));
	void *header = zmq_msg_data(MSG_HEADER(msg));
	size_t hdr_len = zmq_msg_size(MSG_HEADER(msg));

	// servhub never handle response message
	if (memcmp(header + hdr_len - 6, "_reply", 6) == 0)
		return 1;

	// filter mesasage send by servhub-self
	if (snode->type != SPDNET_SUB && strlen(hub->name) == snode->id_len &&
	    memcmp(hub->name, snode->id, snode->id_len) == 0 &&
	    strlen(hub->name) == id_len &&
	    memcmp(hub->name, sockid, id_len) == 0)
		return 1;

	return 0;
}

static int on_pollin(struct servhub *hub, struct spdnet_node *snode)
{
	struct spdnet_msg msg;
	spdnet_msg_init(&msg);
	spdnet_recvmsg(snode, &msg, 0);

	if (filter_msg(hub, &msg, snode) == 0) {
		struct servmsg sm;
		servmsg_init(&sm, &msg, snode);
		handle_msg(hub, &sm);
		if (sm.rc != SERVICE_EASYNCREPLY) {
			finish_msg(hub, &sm);
			spdnet_sendmsg(snode, &sm.response);
		}
		servmsg_close(&sm);
	}

	spdnet_msg_close(&msg);
	return 0;
}

static void
multicast_recvmsg_cb(struct spdnet_node *snode, struct spdnet_msg *msg)
{
	if (filter_msg(snode->user_data, msg, snode) == 0) {
		struct servmsg sm;
		servmsg_init(&sm, msg, snode);
		handle_msg(snode->user_data, &sm);
		servmsg_close(&sm);
	}
	spdnet_recvmsg_async(snode, multicast_recvmsg_cb, 0);
}

int servhub_init(struct servhub *hub, const char *name, const char *router_addr,
                 struct spdnet_nodepool *serv_snodepool,
                 struct spdnet_nodepool *req_snodepool,
                 struct spdnet_multicast *smulticast)
{
	assert(strlen(router_addr) < SPDNET_ADDRESS_SIZE);

	hub->name = name;
	hub->router_addr = router_addr;

	hub->serv_snodepool = serv_snodepool;
	hub->req_snodepool = req_snodepool;
	hub->smulticast = smulticast;

	hub->smulticast->sub.user_data = hub;
	spdnet_nodepool_add(hub->req_snodepool, &hub->smulticast->sub);
	spdnet_recvmsg_async(&hub->smulticast->sub, multicast_recvmsg_cb, 0);

	INIT_LIST_HEAD(&hub->servareas);
	mutex_init(&hub->servareas_lock);

	servhub_register_service(hub, hub->name, services, NULL);
	return 0;
}

int servhub_close(struct servhub *hub)
{
	servhub_unregister_service(hub, hub->name);

	spdnet_nodepool_del(hub->req_snodepool, &hub->smulticast->sub);

	struct servarea *pos, *n;
	list_for_each_entry_safe(pos, n, &hub->servareas, node) {
		servarea_close(pos);
		list_del(&pos->node);
		free(pos);
	}

	mutex_close(&hub->servareas_lock);
	return 0;
}

int servhub_register_service(struct servhub *hub, const char *name,
                             struct service *services,
                             struct spdnet_node **__snode)
{
	struct spdnet_node *snode = spdnet_nodepool_get(hub->serv_snodepool);
	spdnet_setid(snode, name, strlen(name));
	spdnet_setalive(snode, SPDNET_ALIVE_INTERVAL);
	spdnet_connect(snode, hub->router_addr);
	spdnet_register(snode);
	if (__snode) *__snode = snode;

	struct servarea *sa = malloc(sizeof(*sa));
	servarea_init(sa, name);
	servarea_register_service_batch(sa, services);
	mutex_lock(&hub->servareas_lock);
	list_add(&sa->node, &hub->servareas);
	mutex_unlock(&hub->servareas_lock);

	return 0;
}

int servhub_unregister_service(struct servhub *hub, const char *name)
{
	mutex_lock(&hub->servareas_lock);
	struct servarea *sa = find_servarea(hub, name, strlen(name));
	assert(sa);
	list_del(&sa->node);
	list_del(&sa->sb_node);
	mutex_unlock(&hub->servareas_lock);
	servarea_close(sa);
	free(sa);

	// find will increase snode's count, so put twice
	struct spdnet_node *snode =
		spdnet_nodepool_find(hub->serv_snodepool, name);
	assert(snode);
	spdnet_nodepool_put(hub->serv_snodepool, snode);
	spdnet_nodepool_put(hub->serv_snodepool, snode);

	return 0;
}

int servhub_service_call(struct servhub *hub, struct spdnet_msg *msg)
{
	int rc;

	struct servmsg sm;
	servmsg_init(&sm, msg, NULL);
	handle_msg(hub, &sm);
	rc = sm.rc;
	assert(sm.rc != SERVICE_EASYNCREPLY);
	spdnet_msg_move(msg, &sm.response);
	servmsg_close(&sm);

	return rc;
}

int servhub_service_request(struct servhub *hub, struct spdnet_msg *msg)
{
	int rc;
	struct spdnet_node *p = spdnet_nodepool_get(hub->req_snodepool);

	rc = spdnet_connect(p, SPDNET_ROUTER_INNER_ADDRESS);
	assert(rc == 0);
	rc = spdnet_sendmsg(p, msg);
	assert(rc == 0);

	zmq_pollitem_t item;
	item.socket = spdnet_node_get_socket(p);
	item.fd = 0;
	item.events = ZMQ_POLLIN;
	item.revents = 0;
	if (zmq_poll(&item, 1, -1) != 1) {
		rc = -1;
	} else {
		spdnet_recvmsg(p, msg, 0);
		rc = 0;
	}

	spdnet_nodepool_put(hub->req_snodepool, p);
	return rc;
}

int servhub_run(struct servhub *hub)
{
	struct timeval next;
	timers_run(&next);
	assert(next.tv_sec >= 0 || next.tv_usec >= 0);

	// 200 <= timeout <= 1000
	long timeout = next.tv_sec * 1000 + next.tv_usec / 1000;
	timeout = timeout < 1000 ? timeout : 1000;
	timeout = timeout == 0 ? 200 : timeout;
	spdnet_nodepool_poll(hub->serv_snodepool, timeout);

	struct spdnet_node *pos;
	list_for_each_entry(pos, &hub->serv_snodepool->pollins, pollin_node)
		on_pollin(hub, pos);

	spdnet_nodepool_run(hub->req_snodepool);
	return 0;
}
