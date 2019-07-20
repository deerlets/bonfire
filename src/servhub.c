#include "service.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define SERVAREA_NAME "servhub"

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
		"{\"servarea\":\"%s\",\"service\":\"%s\",\"describe\":\"%s\"}";

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
	int len = RESPONSE_SUBFIX_LEN;
	if (memcmp(MSG_HEADER_DATA(msg) + MSG_HEADER_SIZE(msg) - len,
	           RESPONSE_SUBFIX, len) == 0)
		return 1;

	// filter mesasage send by servhub-self
	else if (snode->type != SPDNET_SUB &&
	    strlen(hub->id) == snode->id_len &&
	    memcmp(hub->id, snode->id, snode->id_len) == 0 &&
	    strlen(hub->id) == MSG_SOCKID_SIZE(msg) &&
	    memcmp(hub->id, MSG_SOCKID_DATA(msg), MSG_SOCKID_SIZE(msg)) == 0)
		return 1;

	return 0;
}

static void handle_msg(struct servhub *hub, struct servmsg *sm)
{
	// find servarea
	pthread_mutex_lock(&hub->servareas_lock);
	struct servarea *sa;
	if (!(sa = find_servarea(hub, sm->header, sm->area_len))) {
		pthread_mutex_unlock(&hub->servareas_lock);
		sm->rc = SERVICE_ENOSERV;
		sm->state = SM_HANDLED;
		return;
	}

	// find handler
	service_handler_func_t fn;
	fn = servarea_find_handler(sa, sm->service, sm->service_len);
	pthread_mutex_unlock(&hub->servareas_lock);

	// call handler
	if (!fn) {
		sm->rc = SERVICE_ENOREQ;
		sm->state = SM_HANDLED;
	} else {
		sm->rc = fn(sm);
		if (sm->state < SM_PENDING)
			sm->state = SM_HANDLED;
	}
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
	const char *errmsg = sm->errmsg;
	if (!errmsg) errmsg = service_strerror(sm->rc);
	size_t buflen = 64 + strlen(errmsg) + cnt_len;
	char *buf = malloc(buflen);
	int nr = snprintf(buf, buflen, "{\"errno\":%d, \"errmsg\":\"%s\","
	                  " \"result\":", -sm->rc, errmsg);
	memcpy(buf + nr, cnt, cnt_len);
	buf[nr + cnt_len] = '}';
	buf[nr + cnt_len + 1] = '\0';

	zmq_msg_close(MSG_CONTENT(&sm->response));
	zmq_msg_init_size(MSG_CONTENT(&sm->response), strlen(buf));
	memcpy(MSG_CONTENT_DATA(&sm->response), buf, strlen(buf));
	free(buf);
}

static void do_servmsg(struct servhub *hub)
{
	struct servmsg *pos, *n;
	list_for_each_entry_safe(pos, n, &hub->servmsgs, node) {
		// stage 1: handle raw
		if (pos->state < SM_PENDING) {
			if (hub->prepare_cb)
				hub->prepare_cb(pos);

			if (pos->state < SM_PENDING)
				handle_msg(hub, pos);
		}

		// stage 2: handle intermediate
		assert(pos->state >= SM_PENDING);

		if (pos->state == SM_PENDING)
			continue;

		// stage 3: handle result
		assert(pos->state >= SM_FILTERED);

		if (pos->state != SM_FILTERED) {
			if (pos->state == SM_TIMEOUT)
				pos->rc = SERVICE_ETIMEOUT;

			if (pos->src) {
				finish_msg(hub, pos);
				spdnet_sendmsg(pos->snode, &pos->response);
			}
		}

		if (pos->state == SM_FILTERED)
			hub->servmsg_filtered++;
		else if (pos->state == SM_TIMEOUT)
			hub->servmsg_timeout++;
		else
			hub->servmsg_handled++;
		hub->servmsg_doing--;

		// stage 4: release servmsg
		if (hub->finished_cb)
			hub->finished_cb(pos);
		list_del(&pos->node);
		servmsg_close(pos);
		free(pos);
	}
}

static void recvmsg_cb(struct spdnet_node *snode, struct spdnet_msg *msg)
{
	struct servhub *hub = snode->user_data;

	if (filter_wrong_spdnet_msg(hub, msg, snode) == 0) {
		struct servmsg *sm = malloc(sizeof(*sm));
		servmsg_init(sm, msg, snode);
		list_add(&sm->node, &hub->servmsgs);
		hub->servmsg_total++;
		hub->servmsg_doing++;
	}
	spdnet_recvmsg_async(snode, recvmsg_cb, 0);
}

int servhub_init(struct servhub *hub,
                 const char *id,
                 const char *router_addr,
                 struct spdnet_nodepool *snodepool)
{
	assert(strlen(router_addr) < SPDNET_ADDRESS_SIZE);
	memset(hub, 0, sizeof(*hub));

	hub->id = id;
	hub->router_addr = router_addr;
	hub->snodepool = snodepool;

	hub->prepare_cb = NULL;
	hub->finished_cb = NULL;

	INIT_LIST_HEAD(&hub->servareas);
	pthread_mutex_init(&hub->servareas_lock, NULL);

	INIT_LIST_HEAD(&hub->servmsgs);
	hub->servmsg_total = 0;
	hub->servmsg_doing = 0;
	hub->servmsg_filtered = 0;
	hub->servmsg_timeout = 0;
	hub->servmsg_handled = 0;

	hub->pid = 0;
	hub->service_call_timeout = 1000;

	hub->user_data = NULL;

	servhub_register_servarea(hub, SERVAREA_NAME,
	                          services, id, &hub->snode);
	return 0;
}

int servhub_close(struct servhub *hub)
{
	servhub_unregister_servarea(hub, SERVAREA_NAME, SERVAREA_NAME);

	struct servarea *pos, *n;
	list_for_each_entry_safe(pos, n, &hub->servareas, node) {
		servarea_close(pos);
		list_del(&pos->node);
		free(pos);
	}

	pthread_mutex_destroy(&hub->servareas_lock);
	return 0;
}

int servhub_register_servarea(struct servhub *hub,
                              const char *area_name,
                              struct service *services,
                              const char *sockid,
                              struct spdnet_node **__snode)
{
	if (sockid) {
		struct spdnet_node *snode = spdnet_nodepool_get(hub->snodepool);
		spdnet_setid(snode, sockid, strlen(sockid));
		spdnet_setalive(snode, SPDNET_ALIVE_INTERVAL);
		spdnet_connect(snode, hub->router_addr);
		spdnet_recvmsg_async(snode, recvmsg_cb, 0);
		snode->user_data = hub;
		if (__snode) *__snode = snode;
	}

	struct servarea *sa = malloc(sizeof(*sa));
	servarea_init(sa, area_name);
	servarea_register_services(sa, services);
	pthread_mutex_lock(&hub->servareas_lock);
	list_add(&sa->node, &hub->servareas);
	pthread_mutex_unlock(&hub->servareas_lock);

	return 0;
}

int servhub_unregister_servarea(struct servhub *hub,
                                const char *area_name,
                                const char *sockid)
{
	pthread_mutex_lock(&hub->servareas_lock);
	struct servarea *sa = find_servarea(hub, area_name, strlen(area_name));
	assert(sa);
	list_del(&sa->node);
	pthread_mutex_unlock(&hub->servareas_lock);
	servarea_close(sa);
	free(sa);

	// find will increase snode's count, so put twice
	if (sockid) {
		struct spdnet_node *snode =
			spdnet_nodepool_find(hub->snodepool, sockid);
		if (snode) {
			spdnet_nodepool_put(hub->snodepool, snode);
			spdnet_nodepool_put(hub->snodepool, snode);
		}
	}

	return 0;
}

void servhub_mandate_snode(struct servhub *hub, struct spdnet_node *snode)
{
	snode->user_data = hub;
	spdnet_nodepool_add(hub->snodepool, snode);
	spdnet_recvmsg_async(snode, recvmsg_cb, 0);
}

void servhub_recall_snode(struct servhub *hub, struct spdnet_node *snode)
{
	spdnet_nodepool_del(hub->snodepool, snode);
	snode->recvmsg_cb = NULL;
}

service_prepare_func_t
servhub_set_prepare(struct servhub *hub, service_prepare_func_t prepare_cb)
{
	service_prepare_func_t last = hub->prepare_cb;
	hub->prepare_cb = prepare_cb;
	return last;
}

service_prepare_func_t
servhub_set_finished(struct servhub *hub, service_prepare_func_t finished_cb)
{
	service_prepare_func_t last = hub->finished_cb;
	hub->finished_cb = finished_cb;
	return last;
}

void servhub_set_service_call_timeout(struct servhub *hub, long timeout)
{
	hub->service_call_timeout = timeout;
}

static int
__servhub_service_call_local(struct servhub *hub, struct spdnet_msg *msg)
{
	int rc;

	struct servmsg sm;
	servmsg_init_uninterruptible(&sm, msg, NULL);

	if (hub->prepare_cb)
		hub->prepare_cb(&sm);

	handle_msg(hub, &sm);
	assert(sm.state == SM_HANDLED);

	if (hub->finished_cb)
		hub->finished_cb(&sm);

	rc = sm.rc;
	spdnet_msg_move(msg, &sm.response);
	servmsg_close(&sm);

	return rc;
}

static int
__servhub_service_call(struct servhub *hub, struct spdnet_msg *msg)
{
	int rc;
	struct spdnet_node snode;
	spdnet_node_init(&snode, SPDNET_NODE, hub->snodepool->ctx);

	rc = spdnet_connect(&snode, hub->router_addr);
	assert(rc == 0);
	rc = spdnet_sendmsg(&snode, msg);
	assert(rc == 0);

	zmq_pollitem_t item;
	item.socket = spdnet_node_get_socket(&snode);
	item.fd = 0;
	item.events = ZMQ_POLLIN;
	item.revents = 0;
	if (zmq_poll(&item, 1, hub->service_call_timeout) != 1) {
		rc = -1;
	} else {
		spdnet_recvmsg(&snode, msg, 0);
		rc = 0;
	}

	spdnet_node_close(&snode);
	return rc;
}

int servhub_service_call(struct servhub *hub, struct spdnet_msg *msg)
{
	// Across thread access
	if (pthread_self() != hub->pid) {
		if (MSG_SOCKID_SIZE(msg) == 0) {
			spdnet_frame_close(MSG_SOCKID(msg));
			spdnet_frame_init_size(MSG_SOCKID(msg), strlen(hub->id));
			memcpy(MSG_SOCKID_DATA(msg), hub->id, strlen(hub->id));
		}
		return __servhub_service_call(hub, msg);
	}

	if (MSG_SOCKID_SIZE(msg) == 0)
		return __servhub_service_call_local(hub, msg);

	if ((MSG_SOCKID_SIZE(msg) == strlen(hub->id) &&
	    !memcmp(MSG_SOCKID_DATA(msg), hub->id, strlen(hub->id))))
		return __servhub_service_call_local(hub, msg);

	return __servhub_service_call(hub, msg);
}

int servhub_loop(struct servhub *hub, long timeout)
{
	if (hub->pid == 0)
		hub->pid = pthread_self();
	else
		assert(hub->pid == pthread_self());

	spdnet_nodepool_loop(hub->snodepool, timeout);
	do_servmsg(hub);
	return 0;
}
