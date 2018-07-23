#include "service.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "timer.h"
#include "zsocket.h"

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

static int on_services(struct servmsg *sm)
{
	struct servhub *hub = sm->snode->user_data;

	size_t buflen = 1024;
	char *buf = malloc(buflen);
	int nr = sprintf(buf, "{\"services\": [");
	const char *service_template =
		"{\"service\":\"%s\",\"request\":\"%s\",\"describe\":\"%s\"}";

	struct servarea *pos;
	list_for_each_entry(pos, &hub->servareas, node) {
		struct service *cur;
		list_for_each_entry(cur, &pos->services, node) {
			if (!cur->visible) continue;

			if (buf[nr - 1] != '[')
				buf[nr++] = ',';

			size_t __len = nr + strlen(service_template)
				+ strlen(pos->name) + strlen(cur->name)
				+ (cur->desc ? strlen(cur->desc) : 0);

			// 2 means strlen("]}")
			if (__len + nr + 2 > buflen - 1) {
				buflen += 1024;
				buf = realloc(buf, buflen);
			}

			nr += sprintf(buf + nr, service_template, pos->name,
			              cur->name, cur->desc ? cur->desc : "");
		}
	}

	nr += sprintf(buf + nr, "]}");
	servmsg_respcnt_reset_data(sm, buf, -1);
	free(buf);
	return 0;
}

static struct service services[] = {
	INIT_SERVICE_PRIVATE("blackhole", on_blackhole, NULL),
	INIT_SERVICE("services", on_services, NULL),
	INIT_SERVICE(NULL, NULL, NULL),
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

static int filter_wrong_spdnet_msg(struct servhub *hub, struct spdnet_msg *msg,
                                   struct spdnet_node *snode)
{
	// FIXME: this function is not necessary, remove it in future

	// servhub never handle response message
	if (memcmp(MSG_HEADER_DATA(msg) + MSG_HEADER_SIZE(msg) - 6,
	           "_reply", 6) == 0)
		return 1;

	// filter mesasage send by servhub-self
	else if (snode->type != SPDNET_SUB &&
	    strlen(hub->name) == snode->id_len &&
	    memcmp(hub->name, snode->id, snode->id_len) == 0 &&
	    strlen(hub->name) == MSG_SOCKID_SIZE(msg) &&
	    memcmp(hub->name, MSG_SOCKID_DATA(msg), MSG_SOCKID_SIZE(msg)) == 0)
		return 1;

	return 0;
}

static void handle_msg(struct servhub *hub, struct servmsg *sm)
{
	// find servarea
	mutex_lock(&hub->servareas_lock);
	struct servarea *sa;
	if (!(sa = find_servarea(hub, sm->dest, sm->dest_len))) {
		mutex_unlock(&hub->servareas_lock);
		sm->rc = SERVICE_ENOSERV;
		sm->state = SM_HANDLED;
		return;
	}

	// find handler
	service_handler_func_t fn;
	fn = servarea_find_handler(sa, MSG_HEADER_DATA(&sm->request),
	                           MSG_HEADER_SIZE(&sm->request));
	mutex_unlock(&hub->servareas_lock);
	if (!fn) {
		sm->rc = SERVICE_ENOREQ;
		sm->state = SM_HANDLED;
		return;
	}

	// call service
	sm->rc = fn(sm);
	if (sm->state == SM_RAW_INTERRUPTIBLE ||
	    sm->state == SM_RAW_UNINTERRUPTIBLE)
		sm->state = SM_HANDLED;
}

static void finish_msg(struct servhub *hub, struct servmsg *sm)
{
	const char *cnt = MSG_CONTENT_DATA(&sm->response);
	int cnt_len = MSG_CONTENT_SIZE(&sm->response);

	if (!cnt || !cnt_len) {
		cnt = "null";
		cnt_len = strlen(cnt);
	}

	// 64 is large enough
	size_t buflen = 64 + strlen(service_strerror(sm->rc)) + cnt_len;
	char *buf = malloc(buflen);
	int nr = snprintf(buf, buflen, "{\"errno\":%d, \"errmsg\":\"%s\","
	                  " \"result\":", -sm->rc, service_strerror(sm->rc));
	memcpy(buf + nr, cnt, cnt_len);
	buf[nr + cnt_len] = '}';
	buf[nr + cnt_len + 1] = '\0';

	zmq_msg_close(MSG_CONTENT(&sm->response));
	zmq_msg_init_size(MSG_CONTENT(&sm->response), strlen(buf));
	memcpy(MSG_CONTENT_DATA(&sm->response), buf, strlen(buf));
	free(buf);
}

static int on_pollin(struct servhub *hub, struct spdnet_node *snode)
{
	struct spdnet_msg msg;
	spdnet_msg_init(&msg);
	spdnet_recvmsg(snode, &msg, 0);

	if (filter_wrong_spdnet_msg(hub, &msg, snode) == 0) {
		struct servmsg *sm = malloc(sizeof(*sm));
		servmsg_init(sm, &msg, snode);
		list_add(&sm->node, &hub->servmsgs);
	}

	spdnet_msg_close(&msg);
	return 0;
}

static void
multicast_recvmsg_cb(struct spdnet_node *snode, struct spdnet_msg *msg)
{
	struct servhub *hub = snode->user_data;

	if (filter_wrong_spdnet_msg(snode->user_data, msg, snode) == 0) {
		struct servmsg *sm = malloc(sizeof(*sm));;
		servmsg_init(sm, msg, snode);
		list_add(&sm->node, &hub->servmsgs);
	}
	spdnet_recvmsg_async(snode, multicast_recvmsg_cb, 0);
}

static void do_servmsg(struct servhub *hub)
{
	struct servmsg *pos, *n;
	list_for_each_entry_safe(pos, n, &hub->servmsgs, node) {
		if (pos->state == SM_RAW_INTERRUPTIBLE ||
		    pos->state == SM_RAW_UNINTERRUPTIBLE) {
			if (hub->user_prepare_cb)
				hub->user_prepare_cb(pos);

			if (hub->user_filter_cb)
				hub->user_filter_cb(pos);

			if (pos->state != SM_FILTERD)
				handle_msg(hub, pos);
		}

		assert(pos->state != SM_RAW_UNINTERRUPTIBLE &&
		       pos->state != SM_RAW_INTERRUPTIBLE);

		if (pos->state == SM_PENDING)
			continue;

		if (pos->state == SM_TIMEOUT)
			pos->rc = SERVICE_ETIMEOUT;

		if ((pos->state == SM_HANDLED ||
		     pos->state == SM_TIMEOUT) && pos->src) {
			finish_msg(hub, pos);
			spdnet_sendmsg(pos->snode, &pos->response);
		}

		if (hub->user_finished_cb)
			hub->user_finished_cb(pos);

		list_del(&pos->node);
		servmsg_close(pos);
		free(pos);
	}
}

int servhub_init(struct servhub *hub, const char *name,
                 const char *router_addr,
                 struct spdnet_nodepool *serv_snodepool,
                 struct spdnet_nodepool *req_snodepool,
                 struct spdnet_node *spublish,
                 struct spdnet_multicast *smulticast)
{
	assert(strlen(router_addr) < SPDNET_ADDRESS_SIZE);

	hub->name = name;
	hub->router_addr = router_addr;

	hub->serv_snodepool = serv_snodepool;
	hub->req_snodepool = req_snodepool;
	hub->spublish = spublish;
	hub->smulticast = smulticast;

	hub->smulticast->sub.user_data = hub;
	spdnet_nodepool_add(hub->req_snodepool, &hub->smulticast->sub);
	spdnet_recvmsg_async(&hub->smulticast->sub, multicast_recvmsg_cb, 0);

	hub->user_prepare_cb = NULL;
	hub->user_finished_cb = NULL;
	hub->user_filter_cb = NULL;

	INIT_LIST_HEAD(&hub->servareas);
	mutex_init(&hub->servareas_lock);

	INIT_LIST_HEAD(&hub->servmsgs);

	struct spdnet_node *snode;
	servhub_register_services(hub, hub->name, services, &snode);
	snode->user_data = hub;
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

int servhub_register_services(struct servhub *hub, const char *name,
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
	servarea_register_services(sa, services);
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

service_handler_func_t
servhub_set_prepare(struct servhub *hub, service_handler_func_t prepare_cb)
{
	service_handler_func_t retval = hub->user_prepare_cb;
	hub->user_prepare_cb = prepare_cb;
	return retval;
}

service_handler_func_t
servhub_set_finished(struct servhub *hub, service_handler_func_t finished_cb)
{
	service_handler_func_t retval = hub->user_finished_cb;
	hub->user_finished_cb = finished_cb;
	return retval;
}

service_handler_func_t
servhub_set_filter(struct servhub *hub, service_handler_func_t filter_cb)
{
	service_handler_func_t retval = hub->user_filter_cb;
	hub->user_filter_cb = filter_cb;
	return retval;
}

int servhub_service_call(struct servhub *hub, struct spdnet_msg *msg)
{
	int rc;

	struct servmsg sm;
	servmsg_init_uninterruptible(&sm, msg, NULL);

	if (hub->user_prepare_cb)
		hub->user_prepare_cb(&sm);

	handle_msg(hub, &sm);
	assert(sm.state == SM_HANDLED);

	if (hub->user_finished_cb)
		hub->user_finished_cb(&sm);

	rc = sm.rc;
	spdnet_msg_move(msg, &sm.response);
	servmsg_close(&sm);

	return rc;
}

int servhub_service_request(struct servhub *hub, struct spdnet_msg *msg)
{
	int rc;
	struct spdnet_node *p = spdnet_nodepool_get(hub->req_snodepool);

	rc = spdnet_connect(p, hub->router_addr);
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

	zsocket_loop(0);

	struct spdnet_node *pos;
	list_for_each_entry(pos, &hub->serv_snodepool->pollins, pollin_node)
		on_pollin(hub, pos);

	do_servmsg(hub);

	spdnet_nodepool_run(hub->req_snodepool);
	return 0;
}
