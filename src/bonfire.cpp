#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <spdnet.h>
#include <stdlibx.h>

#include <fstream>
#include <iomanip>
#include <string>
#include <list>
#include <map>
#include <nlohmann/json.hpp>

#include "bonfire-inl.h"

using string = std::string;
using json = nlohmann::json;

#define BONFIRE_BROKER_SOCKID "bonfire-broker-sockid"
#define BONFIRE_SERVICE_INFO "bonfire://service/info"
#define BONFIRE_SERVICE_ADD "bonfire://service/add"
#define BONFIRE_SERVICE_DEL "bonfire://service/del"
#define BONFIRE_FORWARDER_INFO "bonfire://forwarder/info"

#define BONFIRE_STRERROR_GEN(name, msg) case BONFIRE_ ## name: return msg;
const char *bonfire_strerror(int err) {
	switch (err) {
		BONFIRE_ERRNO_MAP(BONFIRE_STRERROR_GEN)
	default:
			return "Unknown errno";
	}
}
#undef BONFIRE_STRERROR_GEN

struct bonfire_service {
	string header;
	string sockid;
	bonfire_service_cb handler;
};

struct bonfire {
	string broker_address;
	string broker_sockid;
	string local_sockid; // for local services

	struct spdnet_ctx *ctx;
	struct spdnet_node *snode; // for local services

	string fwd_pub_addr;
	string fwd_sub_addr;
	struct spdnet_node *pub;
	std::map<string, struct spdnet_node *> subs;
	pthread_mutex_t subs_lock;

	long timeout;

	// services
	std::map<string, struct bonfire_service> services;
	pthread_mutex_t services_lock;

	// bmsg
	std::list<struct bmsg *> bmsgs;

	void *user_data;
	bonfire_service_cb filter_cb;
	bonfire_service_cb prepare_cb;
	bonfire_service_cb finish_cb;

	int msg_total;
	int msg_doing;
	int msg_filtered;
	int msg_handled;
};

static void to_json(json &j, const struct bonfire_service &bs)
{
	j["header"] = bs.header;
	j["sockid"] = bs.sockid;
}

static void from_json(const json &j, bonfire_service &bs)
{
	j.at("header").get_to(bs.header);
	j.at("sockid").get_to(bs.sockid);
	bs.handler = NULL;
}

static void handle_msg(struct bonfire *bf, struct bmsg *bm)
{
	string header((char *)MSG_HEADER_DATA(&bm->request),
	              MSG_HEADER_SIZE(&bm->request));

	auto it = bf->services.find(header);
	if (it == bf->services.end() || !it->second.handler) {
		bmsg_filtered(bm);
		return;
	}

	// call handler
	it->second.handler(bm);
	if (bm->state == BM_RAW)
		bmsg_handled(bm);
}

static void do_all_msg(struct bonfire *bf)
{
	for (auto it = bf->bmsgs.begin();
	     it != bf->bmsgs.end(); ++it) {
		struct bmsg *bm = *it;

		// stage 1: handle raw
		if (bm->state == BM_RAW) {
			if (bf->prepare_cb)
				bf->prepare_cb(bm);

			if (bm->state == BM_RAW)
				handle_msg(bf, bm);
		}

		// stage 2: handle intermediate
		assert(bm->state >= BM_PENDING);

		if (bm->state == BM_PENDING)
			continue;

		// stage 3: handle result
		assert(bm->state >= BM_FILTERED);

		if (bm->state == BM_FILTERED) {
			if (bf->filter_cb)
				bf->filter_cb(bm);
		} else {
			if (bf->finish_cb)
				bf->finish_cb(bm);

			spdnet_sendmsg(bf->snode, &bm->response);
		}

		if (bm->state == BM_FILTERED)
			bf->msg_filtered++;
		else
			bf->msg_handled++;
		bf->msg_doing--;

		// stage 4: release bmsg
		bf->bmsgs.erase(it++);
		bmsg_destroy(bm);
	}
}

static void recvmsg_cb(struct spdnet_node *snode,
                       struct spdnet_msg *msg,
                       void *arg, int flag)
{
	if (flag) {
		fprintf(stderr, "%s: flag => %d\n", __func__, flag);
		return;
	}
	assert(msg);

	struct bonfire *bf = (struct bonfire *)arg;
	struct bmsg *bm = bmsg_new();
	const void *srcid = MSG_SRCID_DATA(msg);
	size_t srcid_len = MSG_SRCID_SIZE(msg);

	// response
	// TODO: need performance optimization
	string resp_header((char *)MSG_HEADER_DATA(msg), MSG_HEADER_SIZE(msg));
	resp_header += BONFIRE_RESPONSE_SUBFIX;
	spdnet_msg_close(&bm->response);
	spdnet_msg_init_data(&bm->response,
	                     srcid, srcid_len,
	                     resp_header.c_str(), -1,
	                     NULL, 0);

	// request
	spdnet_msg_move(&bm->request, msg);

	// bonfire cli
	bm->bf = bf;

	// state
	bm->state = BM_RAW;

	// insert to bmsgs of bonfire
	bf->bmsgs.push_back(bm);
	bf->msg_total++;
	bf->msg_doing++;

	// restart recvmsg async
	spdnet_recvmsg_async(snode, recvmsg_cb, bf, 0);
}

struct bonfire *bonfire_new()
{
	struct bonfire *bf = new struct bonfire;

	bf->broker_address = "";
	bf->broker_sockid = BONFIRE_BROKER_SOCKID;
	char *uuid = uuid_v4_gen();
	bf->local_sockid = uuid;
	free(uuid);

	// ctx
	bf->ctx = spdnet_ctx_new();
	assert(bf->ctx);

	// snode
	bf->snode = spdnet_node_new(bf->ctx, SPDNET_DEALER);
	assert(bf->snode);
	spdnet_set_id(bf->snode, bf->local_sockid.c_str(),
	              bf->local_sockid.size());

	// pub
	bf->pub = NULL;
	pthread_mutex_init(&bf->subs_lock, NULL);

	// timeout
	bf->timeout = BONFIRE_DEFAULT_TIMEOUT;

	// default service
	struct bonfire_service bs;
	bs.header = BONFIRE_SERVICE_INFO;
	bs.sockid = bf->broker_sockid;
	bs.handler = NULL;
	bf->services.insert(std::make_pair(bs.header, bs));
	pthread_mutex_init(&bf->services_lock, NULL);

	// bmsg
	bf->user_data = 0;
	bf->filter_cb = 0;
	bf->prepare_cb = 0;
	bf->finish_cb = 0;

	bf->msg_total = 0;
	bf->msg_doing = 0;
	bf->msg_filtered = 0;
	bf->msg_handled = 0;

	return bf;
}

void bonfire_destroy(struct bonfire *bf)
{
	if (bf->pub)
		spdnet_node_destroy(bf->pub);

	for (auto it = bf->subs.begin(); it != bf->subs.end();) {
		free(spdnet_get_user_data(it->second));
		spdnet_node_destroy(it->second);
		bf->subs.erase(it++);
	}

	pthread_mutex_destroy(&bf->subs_lock);
	pthread_mutex_destroy(&bf->services_lock);

	spdnet_node_destroy(bf->snode);
	spdnet_ctx_destroy(bf->ctx);

	delete bf;
}

int bonfire_connect(struct bonfire *bf, const char *broker_addr)
{
	assert(strlen(broker_addr) < SPDNET_ADDRESS_SIZE);
	bf->broker_address = broker_addr;
	assert(spdnet_connect(bf->snode, bf->broker_address.c_str()) == 0);
	spdnet_recvmsg_async(bf->snode, recvmsg_cb, bf, 0);
	return 0;
}

void bonfire_disconnect(struct bonfire *bf)
{
	spdnet_disconnect(bf->snode);
}

int bonfire_loop(struct bonfire *bf, long timeout)
{
	spdnet_loop(bf->ctx, timeout);
	do_all_msg(bf);
	return 0;
}

void bonfire_get_id(struct bonfire *bf, void *id, size_t *len)
{
	spdnet_get_id(bf->snode, id, len);
}

void bonfire_set_id(struct bonfire *bf, const void *id, size_t len)
{
	spdnet_set_id(bf->snode, id, len);
	bf->local_sockid = string((char *)id, len);
}

void *bonfire_get_user_data(struct bonfire *bf)
{
	return bf->user_data;
}

void bonfire_set_user_data(struct bonfire *bf, void *data)
{
	bf->user_data = data;
}

int bonfire_add_service(struct bonfire *bf, const char *header,
                        bonfire_service_cb handler)
{
	pthread_mutex_lock(&bf->services_lock);
	if (bf->services.find(header) != bf->services.end()) {
		pthread_mutex_unlock(&bf->services_lock);
		errno = BONFIRE_EEXIST;
		return -1;
	}
	pthread_mutex_unlock(&bf->services_lock);

	struct bonfire_service bs = {
		.header = header,
		.sockid = bf->local_sockid,
		.handler = handler,
	};

	char *result = NULL;
	if (bonfire_servcall(bf, BONFIRE_SERVICE_ADD,
	                     json(bs).dump().c_str(), &result))
		return -1;

	try {
		json j = json::parse(result);
		free(result);
		result = NULL;
		if (j["errno"] != 0) {
			errno = j["errno"];
			return -1;
		}
	} catch (json::exception &ex) {
		fprintf(stderr, "%s: %s\n", __func__, ex.what());
		assert(0);
	}

	pthread_mutex_lock(&bf->services_lock);
	bf->services.insert(std::make_pair(bs.header, bs));
	pthread_mutex_unlock(&bf->services_lock);
	return 0;
}

int bonfire_del_service(struct bonfire *bf, const char *header)
{
	pthread_mutex_lock(&bf->services_lock);
	if (bf->services.find(header) == bf->services.end()) {
		pthread_mutex_unlock(&bf->services_lock);
		errno = BONFIRE_ENOTFOUND;
		return -1;
	}
	pthread_mutex_unlock(&bf->services_lock);

	json cnt = {{"header", header}};
	char *result = NULL;
	if (bonfire_servcall(bf, BONFIRE_SERVICE_DEL,
	                     cnt.dump().c_str(), &result))
		return -1;

	try {
		json j = json::parse(result);
		free(result);
		result = NULL;
		if (j["errno"] != 0) {
			errno = j["errno"];
			return -1;
		}
	} catch (json::exception &ex) {
		fprintf(stderr, "%s: %s\n", __func__, ex.what());
		assert(0);
	}

	pthread_mutex_lock(&bf->services_lock);
	auto it = bf->services.find(header);
	assert(it != bf->services.end());
	bf->services.erase(it);
	pthread_mutex_unlock(&bf->services_lock);
	return 0;
}

void bonfire_set_servcall_timeout(struct bonfire *bf, long timeout)
{
	bf->timeout = timeout;
}

static int servcall(struct bonfire *bf,
                    const char *sockid,
                    const char *header,
                    const char *content,
                    char **result)
{
	struct spdnet_node *snode = spdnet_node_new(bf->ctx, SPDNET_DEALER);
	assert(snode);
	assert(spdnet_connect(snode, bf->broker_address.c_str()) == 0);

	struct spdnet_msg tmp;
	SPDNET_MSG_INIT_DATA(&tmp, sockid, header, content);
	assert(spdnet_sendmsg(snode, &tmp) == 0);
	if (spdnet_recvmsg_timeout(snode, &tmp, bf->timeout)) {
		spdnet_msg_close(&tmp);
		spdnet_node_destroy(snode);
		errno = BONFIRE_ETIMEOUT;
		return -1;
	}

	if (result) {
		string cnt((char *)MSG_CONTENT_DATA(&tmp),
		           MSG_CONTENT_SIZE(&tmp));
		*result = strdup(cnt.c_str());
	}

	spdnet_msg_close(&tmp);
	spdnet_node_destroy(snode);
	return 0;
}

static int call_service_info(struct bonfire *bf,
                             const char *info_header,
                             struct bonfire_service *bs)
{
	assert(string(info_header) != BONFIRE_SERVICE_INFO);

	json j = {{"header", info_header}};
	char *result = NULL;

	if (servcall(bf, bf->broker_sockid.c_str(),
	             BONFIRE_SERVICE_INFO,
	             j.dump().c_str(), &result))
		return -1;

	try {
		json j = json::parse(result);
		free(result);
		result = NULL;

		if (j["errno"] != 0) {
			errno = j["errno"];
			return -1;
		}

		*bs = j["result"];
	} catch (json::exception &ex) {
		fprintf(stderr, "%s: %s\n", __func__, ex.what());
		assert(0);
	}

	return 0;
}

int bonfire_servcall(struct bonfire *bf,
                     const char *header,
                     const char *content,
                     char **result)
{
	string sockid;

	pthread_mutex_lock(&bf->services_lock);
	auto it = bf->services.find(header);
	if (it != bf->services.end()) {
		sockid = it->second.sockid;
		pthread_mutex_unlock(&bf->services_lock);
	} else {
		pthread_mutex_unlock(&bf->services_lock);
		struct bonfire_service bs;
		if (call_service_info(bf, header, &bs))
			return -1;
		sockid = bs.sockid;
		pthread_mutex_lock(&bf->services_lock);
		bf->services.insert(std::make_pair(bs.header, bs));
		pthread_mutex_unlock(&bf->services_lock);
	}

	return servcall(bf, sockid.c_str(), header, content, result);
}

struct servcall_struct {
	struct bonfire *bf;
	bonfire_servcall_cb cb;
	void *arg;

	servcall_struct(struct bonfire *bf, bonfire_servcall_cb cb, void *arg) {
		this->bf = bf;
		this->cb = cb;
		this->arg = arg;
	}
};

static void servcall_cb(struct spdnet_node *snode,
                        struct spdnet_msg *msg,
                        void *arg, int flag)
{
	servcall_struct *as = static_cast<servcall_struct *>(arg);

	if (flag) {
		as->cb(as->bf, NULL, 0, as->arg, BONFIRE_ETIMEOUT);
	} else {
		as->cb(as->bf, MSG_CONTENT_DATA(msg), MSG_CONTENT_SIZE(msg),
		       as->arg, BONFIRE_EOK);
	}

	delete as;
	spdnet_node_destroy(snode);
}

static void servcall_async(struct bonfire *bf,
                           const char *sockid,
                           const char *header,
                           const char *content,
                           bonfire_servcall_cb cb,
                           void *arg)
{
	struct spdnet_node *snode = spdnet_node_new(bf->ctx, SPDNET_DEALER);
	assert(snode);
	assert(spdnet_connect(snode, bf->broker_address.c_str()) == 0);

	struct spdnet_msg tmp;
	SPDNET_MSG_INIT_DATA(&tmp, sockid, header, content);
	assert(spdnet_sendmsg(snode, &tmp) == 0);
	spdnet_msg_close(&tmp);

	servcall_struct *as = new servcall_struct(bf, cb, arg);
	spdnet_recvmsg_async(snode, servcall_cb, as, bf->timeout);
}

void bonfire_servcall_async(struct bonfire *bf,
                            const char *header,
                            const char *content,
                            bonfire_servcall_cb cb,
                            void *arg)
{
	string sockid;

	pthread_mutex_lock(&bf->services_lock);
	auto it = bf->services.find(header);
	if (it != bf->services.end()) {
		sockid = it->second.sockid;
		pthread_mutex_unlock(&bf->services_lock);
	} else {
		pthread_mutex_unlock(&bf->services_lock);
		struct bonfire_service bs;
		if (call_service_info(bf, header, &bs)) {
			assert(errno != BONFIRE_EOK);
			cb(bf, NULL, 0, arg, errno);
			return;
		}
		sockid = bs.sockid;
		pthread_mutex_lock(&bf->services_lock);
		bf->services.insert(std::make_pair(bs.header, bs));
		pthread_mutex_unlock(&bf->services_lock);
	}

	servcall_async(bf, sockid.c_str(), header, content, cb, arg);
}

struct subscribe_struct {
	struct bonfire *bf;
	bonfire_subscribe_cb cb;
	void *arg;
};

static void subscribe_cb(struct spdnet_node *snode,
                         struct spdnet_msg *msg,
                         void *arg, int flag)
{
	subscribe_struct *ss = static_cast<subscribe_struct *>(
		spdnet_get_user_data(snode));
	assert(flag == 0);
	assert(msg);
	ss->cb(ss->bf, MSG_CONTENT_DATA(msg),
	       MSG_CONTENT_SIZE(msg),
	       ss->arg, BONFIRE_EOK);
	spdnet_recvmsg_async(snode, subscribe_cb, NULL, 0);
}

static int get_forwarder_info(struct bonfire *bf)
{
	char *result = NULL;

	if (bonfire_servcall(bf, BONFIRE_FORWARDER_INFO, NULL, &result))
		return -1;

	try {
		json j = json::parse(result);
		free(result);
		result = NULL;

		assert(j["errno"] == 0);
		bf->fwd_pub_addr = j["result"]["pub_addr"];
		bf->fwd_sub_addr = j["result"]["sub_addr"];
	} catch (json::exception &ex) {
		fprintf(stderr, "%s: %s\n", __func__, ex.what());
		assert(0);
	}

	return 0;
}

int bonfire_publish(struct bonfire *bf, const char *topic, const char *content)
{
	if (bf->fwd_sub_addr.empty() && get_forwarder_info(bf))
		return -1;

	if (bf->pub == NULL) {
		bf->pub = spdnet_node_new(bf->ctx, SPDNET_PUB);
		spdnet_connect(bf->pub, bf->fwd_sub_addr.c_str());
		sleep(1);
	}
	assert(bf->pub);

	struct spdnet_msg msg;
	SPDNET_MSG_INIT_DATA(&msg, NULL, topic, content);
	spdnet_sendmsg(bf->pub, &msg);
	spdnet_msg_close(&msg);

	return 0;
}

int bonfire_subscribe(struct bonfire *bf,
                      const char *topic,
                      bonfire_subscribe_cb cb,
                      void *arg)
{
	if (bf->fwd_pub_addr.empty() && get_forwarder_info(bf))
		return -1;

	pthread_mutex_lock(&bf->subs_lock);
	if (bf->subs.find(topic) != bf->subs.end()) {
		pthread_mutex_unlock(&bf->subs_lock);
		errno = BONFIRE_EEXIST;
		return -1;
	}
	pthread_mutex_unlock(&bf->subs_lock);

	struct spdnet_node *sub = spdnet_node_new(bf->ctx, SPDNET_SUB);
	spdnet_connect(sub, bf->fwd_pub_addr.c_str());
	spdnet_set_filter(sub, topic, strlen(topic));

	subscribe_struct *ss = (subscribe_struct *)malloc(sizeof(*ss));
	ss->bf = bf;
	ss->cb = cb;
	ss->arg = arg;
	spdnet_set_user_data(sub, ss);
	spdnet_recvmsg_async(sub, subscribe_cb, NULL, 0);

	pthread_mutex_lock(&bf->subs_lock);
	bf->subs.insert(std::make_pair(topic, sub));
	pthread_mutex_unlock(&bf->subs_lock);
	return 0;
}

int bonfire_unsubscribe(struct bonfire *bf, const char *topic)
{
	pthread_mutex_lock(&bf->subs_lock);
	auto it = bf->subs.find(topic);
	if (it == bf->subs.end()) {
		pthread_mutex_unlock(&bf->subs_lock);
		errno = BONFIRE_ENOTFOUND;
		return -1;
	}

	subscribe_struct *ss = (subscribe_struct *)
		spdnet_get_user_data(it->second);
	ss->cb(bf, NULL, 0, ss->arg, BONFIRE_ECANCEL);
	free(ss);

	spdnet_node_destroy(it->second);
	bf->subs.erase(it);
	pthread_mutex_unlock(&bf->subs_lock);

	return 0;
}

/*
 * bonfire broker
 */

typedef int (*bonfire_broker_filter)(struct bmsg *bm);

struct bonfire_broker {
	struct spdnet_ctx *ctx;

	string router_addr;
	string router_id;
	struct spdnet_node *router;
	bonfire_broker_filter filter;

	string fwd_pub_addr;
	string fwd_sub_addr;
	struct spdnet_forwarder *fwd;

	struct bonfire *bf;

	string cache_file;
};

static inline json unpack(struct spdnet_msg *msg)
{
	return json::parse((char *)MSG_CONTENT_DATA(msg),
	                   (char *)MSG_CONTENT_DATA(msg)
	                   + MSG_CONTENT_SIZE(msg));
}

static inline void pack(struct bmsg *bm, int err, json cnt)
{
	json resp = {
		{"errno", err},
		{"errmsg", bonfire_strerror(err)},
		{"result", cnt}
	};
	bmsg_write_response(bm, resp.dump().c_str());
}

static void load_cache(struct bonfire_broker *bbrk)
{
	if (bbrk->cache_file.empty())
		return;

	std::ifstream ifs(bbrk->cache_file);

	try {
		json j = json::parse(ifs);
		for (auto it = j["services"].begin();
		     it != j["services"].end(); ++it) {
			struct bonfire_service bs = *it;
			bbrk->bf->services.insert(
				std::make_pair(bs.header, bs));
		}
	} catch (json::exception &ex) {
		fprintf(stderr, "%s: %s\n", __func__, ex.what());
	}

	ifs.close();
}

static void save_cache(struct bonfire_broker *bbrk)
{
	if (bbrk->cache_file.empty())
		return;

	std::ofstream ofs(bbrk->cache_file);

	json cnt = {{"services", json::array()}};
	int i = 0;

	for (auto &item : bbrk->bf->services)
		cnt["services"][i++] = item.second;

	ofs << std::setw(4) << cnt << std::endl;
	ofs.close();
}

static void on_service_info(struct bmsg *bm)
{
	struct bonfire_broker *bbrk = (struct bonfire_broker *)
		bonfire_get_user_data(bmsg_get_bonfire(bm));

	try {
		json cnt;
		if (MSG_CONTENT_SIZE(&bm->request))
			cnt = unpack(&bm->request);
		if (cnt.find("header") != cnt.end()) {
			auto it = bbrk->bf->services.find(cnt["header"]);
			if (it != bbrk->bf->services.end()) {
				pack(bm, BONFIRE_EOK, json(it->second));
				return;
			}

			pack(bm, BONFIRE_ENOTFOUND, nullptr);
			return;
		}
	} catch (json::exception &ex) {
		fprintf(stderr, "%s: %s\n", __func__, ex.what());
		pack(bm, BONFIRE_EINVAL, nullptr);
		return;
	}

	json cnt = json::array();
	int i = 0;

	for (auto &item : bbrk->bf->services)
		cnt[i++] = item.second;

	pack(bm, BONFIRE_EOK, cnt);
}

static void on_service_add(struct bmsg *bm)
{
	struct bonfire_broker *bbrk = (struct bonfire_broker *)
		bonfire_get_user_data(bmsg_get_bonfire(bm));
	struct bonfire_service bs;

	try {
		bs = unpack(&bm->request);
	} catch (json::exception &ex) {
		fprintf(stderr, "%s: %s\n", __func__, ex.what());
		pack(bm, BONFIRE_EINVAL, nullptr);
		return;
	}

	if (bbrk->bf->services.find(bs.header) !=
	    bbrk->bf->services.end()) {
		auto it = bbrk->bf->services.find(bs.header);
		fprintf(stderr, "%s: old_sockid => %s, new_sockid => %s\n",
		        __func__, it->second.sockid.c_str(), bs.sockid.c_str());
		bbrk->bf->services.erase(it);
		//pack(bm, BONFIRE_EEXIST, nullptr);
		//return;
	}

	bbrk->bf->services.insert(std::make_pair(bs.header, bs));
	save_cache(bbrk);
	pack(bm, BONFIRE_EOK, nullptr);
}

static void on_service_del(struct bmsg *bm)
{
	struct bonfire_broker *bbrk = (struct bonfire_broker *)
		bonfire_get_user_data(bmsg_get_bonfire(bm));
	string header;

	try {
		json cnt = unpack(&bm->request);
		header = cnt["header"];
	} catch (json::exception &ex) {
		fprintf(stderr, "%s: %s\n", __func__, ex.what());
		pack(bm, BONFIRE_EINVAL, nullptr);
		return;
	}

	auto it = bbrk->bf->services.find(header);
	if (it == bbrk->bf->services.end()) {
		pack(bm, BONFIRE_ENOTFOUND, nullptr);
		return;
	}

	bbrk->bf->services.erase(it);
	save_cache(bbrk);
	pack(bm, BONFIRE_EOK, nullptr);
}

static void on_forwarder_info(struct bmsg *bm)
{
	struct bonfire_broker *bbrk = (struct bonfire_broker *)
		bonfire_get_user_data(bmsg_get_bonfire(bm));

	json cnt = {
		{"pub_addr", bbrk->fwd_pub_addr},
		{"sub_addr", bbrk->fwd_sub_addr},
	};

	pack(bm, BONFIRE_EOK, cnt);
}

static void router_recvmsg_cb(struct spdnet_node *snode,
                              struct spdnet_msg *msg,
                              void *arg, int flag)
{
	if (flag) {
		fprintf(stderr, "[%s]: flag => %d\n", __func__, flag);
		return;
	}
	assert(msg);

	struct bonfire_broker *bbrk =
		(struct bonfire_broker *)spdnet_get_user_data(snode);
	if (bbrk->filter) {
		struct bmsg *bm = bmsg_new();
		spdnet_msg_copy(&bm->request, msg);
		int rc = bbrk->filter(bm);
		bmsg_destroy(bm);
		if (rc) return;
	}

	spdnet_builtin_router_recvmsg_cb(snode, msg, arg, flag);
}

struct bonfire_broker *bonfire_broker_new(const char *listen_addr,
                                          const char *pub_addr,
                                          const char *sub_addr)
{
	struct bonfire_broker *bbrk = new struct bonfire_broker;
	assert(strlen(listen_addr) < SPDNET_ADDRESS_SIZE);

	// ctx
	bbrk->ctx = spdnet_ctx_new();
	assert(bbrk->ctx);

	// router
	bbrk->router_addr = listen_addr;
	char *uuid = uuid_v4_gen();
	bbrk->router_id = uuid;
	free(uuid);
	bbrk->router = spdnet_node_new(bbrk->ctx, SPDNET_ROUTER);
	spdnet_set_id(bbrk->router, bbrk->router_id.c_str(),
	              bbrk->router_id.size());
	assert(bbrk->router);
	assert(spdnet_bind(bbrk->router, listen_addr) == 0);
	spdnet_recvmsg_async(bbrk->router, router_recvmsg_cb, NULL, 0);
	spdnet_set_user_data(bbrk->router, bbrk);
	bbrk->filter = NULL;

	// forwarder
	bbrk->fwd_pub_addr = pub_addr;
	bbrk->fwd_sub_addr = sub_addr;
	bbrk->fwd = spdnet_forwarder_new(bbrk->ctx);
	assert(spdnet_forwarder_bind(bbrk->fwd, pub_addr, sub_addr) == 0);

	// bonfire cli
	bbrk->bf = bonfire_new();
	assert(bbrk->bf);
	bonfire_set_id(bbrk->bf, BONFIRE_BROKER_SOCKID,
	               strlen(BONFIRE_BROKER_SOCKID));
	bonfire_set_user_data(bbrk->bf, bbrk);
	bonfire_connect(bbrk->bf, listen_addr);

	struct bonfire_service bs = {};
	bs.sockid = BONFIRE_BROKER_SOCKID;
	bbrk->bf->services.clear();

	bs.header = BONFIRE_SERVICE_INFO;
	bs.handler = on_service_info;
	bbrk->bf->services.insert(std::make_pair(bs.header, bs));

	bs.header = BONFIRE_SERVICE_ADD;
	bs.handler = on_service_add;
	bbrk->bf->services.insert(std::make_pair(bs.header, bs));

	bs.header = BONFIRE_SERVICE_DEL;
	bs.handler = on_service_del;
	bbrk->bf->services.insert(std::make_pair(bs.header, bs));

	bs.header = BONFIRE_FORWARDER_INFO;
	bs.handler = on_forwarder_info;
	bbrk->bf->services.insert(std::make_pair(bs.header, bs));

	return bbrk;
}

void bonfire_broker_destroy(struct bonfire_broker *bbrk)
{
	bonfire_destroy(bbrk->bf);
	spdnet_forwarder_destroy(bbrk->fwd);
	spdnet_node_destroy(bbrk->router);
	spdnet_ctx_destroy(bbrk->ctx);

	delete bbrk;
}

int bonfire_broker_loop(struct bonfire_broker *bbrk, long timeout)
{
	spdnet_loop(bbrk->ctx, timeout);
	bonfire_loop(bbrk->bf, 0);
	return 0;
}

void bonfire_broker_set_filter(struct bonfire_broker *bbrk,
                               bonfire_broker_filter_cb cb)
{
	bbrk->filter = cb;
}

void bonfire_broker_set_gateway(struct bonfire_broker *bbrk,
                                const char *gateway_addr)
{
	char gateway_id[SPDNET_SOCKID_SIZE];
	size_t gateway_len;

	spdnet_associate(bbrk->router, gateway_addr, gateway_id, &gateway_len);
	spdnet_set_gateway(bbrk->router, gateway_id, gateway_len);
}

void bonfire_broker_set_cache_file(struct bonfire_broker *bbrk,
                                   const char *cache_file)
{
	bbrk->cache_file = cache_file;
	load_cache(bbrk);
}
