#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <spdnet.h>

#include <iostream>
#include <fstream>
#include <iomanip>
#include <string>
#include <list>
#include <map>
#include <nlohmann/json.hpp>

#include "bonfire-inl.h"

using string = std::string;
using json = nlohmann::json;

#define BONFIRE_SERVICE_INFO "bonfire://service/info"
#define BONFIRE_SERVICE_ADD "bonfire://service/add"
#define BONFIRE_SERVICE_DEL "bonfire://service/del"
#define BONFIRE_FORWARDER_INFO "bonfire://forwarder/info"

struct bonfire_service {
	string header;
	string sockid;
	int load_level;
	bonfire_service_cb handler;
};

struct bonfire {
	string remote_address;
	string remote_sockid;
	string local_sockid; // for local services

	void *ctx;
	void *snodepool;
	void *snode; // for local services

	string fwd_pub_addr;
	string fwd_sub_addr;
	void *pub;
	std::map<string, void *> subs;

	long timeout;

	// services
	std::map<string, struct bonfire_service> services;
	std::map<string, struct bonfire_service> local_services;

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

static void to_json(json &j, const struct bonfire_service &sv)
{
	j["header"] = sv.header;
	j["sockid"] = sv.sockid;
	j["load_level"] = sv.load_level;
}

static void from_json(const json &j, bonfire_service &sv)
{
	j.at("header").get_to(sv.header);
	j.at("sockid").get_to(sv.sockid);
	j.at("load_level").get_to(sv.load_level);
}

static void handle_msg(struct bonfire *bf, struct bmsg *bm)
{
	string header((char *)MSG_HEADER_DATA(&bm->request),
	              MSG_HEADER_SIZE(&bm->request));

	auto it = bf->local_services.find(header);
	if (it == bf->local_services.end()) {
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

static void recvmsg_cb(void *snode, struct spdnet_msg *msg, void *arg)
{
	struct bonfire *bf = (struct bonfire *)arg;

	const void *srcid = MSG_SOCKID_DATA(msg);
	size_t srcid_len = MSG_SOCKID_SIZE(msg);

	char dstid[SPDNET_SOCKID_SIZE];
	size_t dstid_len;
	spdnet_get_id(snode, dstid, &dstid_len);

	struct bmsg *bm = bmsg_new();

	// request
	spdnet_msg_close(&bm->request);
	spdnet_msg_init_data(&bm->request, dstid, dstid_len,
	                     MSG_HEADER_DATA(msg), MSG_HEADER_SIZE(msg),
	                     MSG_CONTENT_DATA(msg), MSG_CONTENT_SIZE(msg));

	// response
	// TODO: need performance optimization
	string resp_header((char *)MSG_HEADER_DATA(msg), MSG_HEADER_SIZE(msg));
	resp_header += BONFIRE_RESPONSE_SUBFIX;
	spdnet_msg_close(&bm->response);
	spdnet_msg_init_data(&bm->response,
	                     srcid, srcid_len,
	                     resp_header.c_str(), -1,
	                     NULL, 0);

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

struct bonfire *bonfire_new(const char *remote_addr,
                            const char *remote_id,
                            const char *local_id)
{
	struct bonfire *bf = new struct bonfire;

	assert(strlen(remote_addr) < SPDNET_ADDRESS_SIZE);
	assert(strlen(remote_id) < SPDNET_SOCKID_SIZE);
	assert(strlen(local_id) < SPDNET_SOCKID_SIZE);
	bf->remote_address = remote_addr;
	bf->remote_sockid = remote_id;
	bf->local_sockid = local_id;

	// ctx
	bf->ctx = spdnet_ctx_new();
	assert(bf->ctx);

	// snodepool
	bf->snodepool = spdnet_nodepool_new(bf->ctx, 50);
	assert(bf->snodepool);

	// snode
	bf->snode = spdnet_nodepool_get(bf->snodepool);
	assert(bf->snode);
	spdnet_set_id(bf->snode, bf->local_sockid.c_str(),
	              bf->local_sockid.size());
	assert(spdnet_connect(bf->snode, bf->remote_address.c_str()) == 0);
	spdnet_recvmsg_async(bf->snode, recvmsg_cb, bf, 0);

	// pub
	bf->pub = NULL;

	// timeout
	bf->timeout = BONFIRE_DEFAULT_SERVCALL_TIMEOUT;

	// default service
	struct bonfire_service bs;
	bs.header = BONFIRE_SERVICE_INFO;
	bs.sockid = remote_id;
	bf->services.insert(std::make_pair(bs.header, bs));

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
		assert(spdnet_node_destroy(bf->pub) == 0);

	for (auto it = bf->subs.begin(); it != bf->subs.end();) {
		spdnet_nodepool_del(bf->snodepool, it->second);
		free(spdnet_get_user_data(it->second));
		assert(spdnet_node_destroy(it->second) == 0);
		bf->subs.erase(it++);
	}

	spdnet_nodepool_put(bf->snodepool, bf->snode);
	spdnet_nodepool_destroy(bf->snodepool);
	spdnet_ctx_destroy(bf->ctx);

	delete bf;
}

int bonfire_loop(struct bonfire *bf, long timeout)
{
	spdnet_nodepool_loop(bf->snodepool, timeout);
	do_all_msg(bf);
	return 0;
}

void *bonfire_get_user_data(struct bonfire *bf)
{
	return bf->user_data;
}

void bonfire_set_user_data(struct bonfire *bf, void *data)
{
	bf->user_data = data;
}

void bonfire_add_service(struct bonfire *bf, const char *header,
                        bonfire_service_cb handler)
{
	if (bf->local_services.find(header) != bf->local_services.end())
		return;

	struct bonfire_service bs = {
		.header = header,
		.sockid = bf->local_sockid,
		.load_level = 0,
		.handler = handler,
	};
	bf->local_services.insert(std::make_pair(bs.header, bs));
}

void bonfire_del_service(struct bonfire *bf, const char *header)
{
	auto it = bf->local_services.find(header);
	if (it == bf->local_services.end())
		return;
	bf->local_services.erase(it);
}

static int pull_service_from_remote(struct bonfire *bf)
{
	char *result = NULL;

	if (bonfire_servcall(bf, BONFIRE_SERVICE_INFO, NULL, &result))
		return -1;

	try {
		json j = json::parse(result);
		free(result);
		result = NULL;

		if (j["errno"] != 0)
			return -1;
		json s = j["result"];
		std::map<string, struct bonfire_service> services;
		for (auto it = s.begin(); it != s.end(); ++it) {
			struct bonfire_service bs = *it;
			services.insert(std::make_pair(bs.header, bs));
		}
		bf->services = services;
	} catch (json::exception &ex) {
		std::cerr << __func__ << ":" << ex.what() << std::endl;
		if (result) free(result);
		return -1;
	}

	return 0;
}


static int push_local_service_to_remote(struct bonfire *bf)
{
	char *result = NULL;

	for (auto &item : bf->local_services) {
		if (bf->services.find(item.second.header) != bf->services.end())
			continue;

		json cnt = item.second;

		if (bonfire_servcall(bf, BONFIRE_SERVICE_ADD,
		                     cnt.dump().c_str(), &result))
			return -1;

		try {
			json j = json::parse(result);
			free(result);
			result = NULL;
			if (j["errno"] != 0)
				return -1;
		} catch (json::exception &ex) {
			std::cerr << __func__ << ":" << ex.what() << std::endl;
			if (result) free(result);
			return -1;
		}

		bf->services.insert(item);
	}

	// TODO: delete remote service that not in local_services

	return 0;
}

int bonfire_servsync(struct bonfire *bf)
{
	if (pull_service_from_remote(bf))
		return -1;

	if (push_local_service_to_remote(bf))
		return -1;

	return 0;
}

void bonfire_set_servcall_timeout(struct bonfire *bf, long timeout)
{
	bf->timeout = timeout;
}

int bonfire_servcall(struct bonfire *bf,
                     const char *header,
                     const char *content,
                     char **result)
{
	// find service
	auto it = bf->services.find(header);
	if (it == bf->services.end()) {
		assert(string(header) != BONFIRE_SERVICE_INFO);

		json j = {{"header", header}};
		char *result = NULL;

		if (bonfire_servcall(bf, BONFIRE_SERVICE_INFO,
		                     j.dump().c_str(), &result))
			return BONFIRE_SERVCALL_TIMEOUT;

		try {
			json j = json::parse(result);
			free(result);
			result = NULL;

			if (j["errno"] != 0)
				return BONFIRE_SERVCALL_NOSERV;

			struct bonfire_service bs = j["result"];
			bf->services.insert(std::make_pair(bs.header, bs));
			it = bf->services.find(header);
			assert(it != bf->services.end());
		} catch (json::exception &ex) {
			std::cerr << __func__ << ":" << ex.what() << std::endl;
			if (result) free(result);
			assert(0);
		}
	}

	// call remote service
	void *snode = spdnet_nodepool_get(bf->snodepool);
	assert(snode);
	assert(spdnet_connect(snode, bf->remote_address.c_str()) == 0);

	struct spdnet_msg tmp;
	SPDNET_MSG_INIT_DATA(&tmp, it->second.sockid.c_str(), header, content);
	assert(spdnet_sendmsg(snode, &tmp) == 0);
	if (spdnet_recvmsg_timeout(snode, &tmp, 0, bf->timeout)) {
		spdnet_msg_close(&tmp);
		spdnet_nodepool_put(bf->snodepool, snode);
		return -1;
	}

	string cnt((char *)MSG_CONTENT_DATA(&tmp), MSG_CONTENT_SIZE(&tmp));
	if (result) *result = strdup(cnt.c_str());

	spdnet_msg_close(&tmp);
	spdnet_nodepool_put(bf->snodepool, snode);
	return 0;
}

struct async_struct {
	struct bonfire *bf;
	bonfire_servcall_cb cb;
	void *arg;
	string header;
	string content;

	async_struct(struct bonfire *bf, bonfire_servcall_cb cb, void *arg,
	             const char *header, const char *content) {
		this->bf = bf;
		this->cb = cb;
		this->arg = arg;
		if (header)
			this->header = header;
		if (content)
			this->content = content;
	}

	async_struct(struct bonfire *bf, bonfire_servcall_cb cb, void *arg) {
		this->bf = bf;
		this->cb = cb;
		this->arg = arg;

		// why can't use constructor chain ?
		//async_struct(bf, cb, arg, NULL, NULL);
	}
};

static void async_cb(void *snode, struct spdnet_msg *msg, void *arg)
{
	async_struct *as = static_cast<async_struct *>(arg);
	int flag = BONFIRE_SERVCALL_OK;

	if (!msg) {
		flag = BONFIRE_SERVCALL_TIMEOUT;
		as->cb(NULL, 0, as->arg, flag);
	} else {
		as->cb(MSG_CONTENT_DATA(msg),
		       MSG_CONTENT_SIZE(msg),
		       as->arg, flag);
	}

	spdnet_nodepool_put(as->bf->snodepool, snode);
}

static void service_info_cb(const void *resp, size_t len, void *arg, int flag)
{
	struct async_struct *as = (struct async_struct *)arg;
	struct bonfire *bf = as->bf;

	if (flag) goto errout;

	try {
		json j = json::parse((char *)resp, (char *)resp + len);
		if (j["errno"] != 0) goto errout;

		struct bonfire_service bs = j["result"];
		bf->services.insert(std::make_pair(bs.header, bs));

		// call remote service
		void *snode = spdnet_nodepool_get(bf->snodepool);
		assert(snode);
		assert(spdnet_connect(snode, bf->remote_address.c_str()) == 0);

		struct spdnet_msg tmp;
		SPDNET_MSG_INIT_DATA(&tmp, bs.sockid.c_str(),
		                     as->header.c_str(),
		                     as->content.c_str());
		assert(spdnet_sendmsg(snode, &tmp) == 0);
		spdnet_msg_close(&tmp);

		spdnet_recvmsg_async(snode, async_cb, as, bf->timeout);
	} catch (json::exception &ex) {
		std::cerr << __func__ << ":" << ex.what() << std::endl;
	}

	return;
errout:
	as->cb(NULL, 0, as->arg, BONFIRE_SERVCALL_NOSERV);
	delete as;
}

void bonfire_servcall_async(struct bonfire *bf,
                            const char *header,
                            const char *content,
                            bonfire_servcall_cb cb,
                            void *arg)
{
	// find service
	auto it = bf->services.find(header);
	if (it == bf->services.end()) {
		assert(string(header) != BONFIRE_SERVICE_INFO);

		json j = {{"header", header}};
		async_struct *as = new async_struct(
			bf, cb, arg, header, content);
		bonfire_servcall_async(bf, BONFIRE_SERVICE_INFO,
		                       j.dump().c_str(), service_info_cb, as);
		return;
	}

	// call remote service
	void *snode = spdnet_nodepool_get(bf->snodepool);
	assert(snode);
	assert(spdnet_connect(snode, bf->remote_address.c_str()) == 0);

	struct spdnet_msg tmp;
	SPDNET_MSG_INIT_DATA(&tmp, it->second.sockid.c_str(), header, content);
	assert(spdnet_sendmsg(snode, &tmp) == 0);
	spdnet_msg_close(&tmp);

	async_struct *as = new async_struct(bf, cb, arg);
	spdnet_recvmsg_async(snode, async_cb, as, bf->timeout);
}

struct subscribe_struct {
	bonfire_subscribe_cb cb;
	void *arg;
};

static void subscribe_cb(void *snode, struct spdnet_msg *msg, void *arg)
{
	subscribe_struct *ss = static_cast<subscribe_struct *>(
		spdnet_get_user_data(snode));
	assert(msg);
	ss->cb(MSG_CONTENT_DATA(msg), MSG_CONTENT_SIZE(msg), ss->arg);
	spdnet_recvmsg_async(snode, subscribe_cb, NULL, 0);
}

static int get_forwarder_info(struct bonfire *bf)
{
	char *result = NULL;

	if (bonfire_servcall(bf, BONFIRE_FORWARDER_INFO, NULL, &result))
		return BONFIRE_SERVCALL_TIMEOUT;

	try {
		json j = json::parse(result);
		free(result);
		result = NULL;

		assert(j["errno"] == 0);
		bf->fwd_pub_addr = j["result"]["pub_addr"];
		bf->fwd_sub_addr = j["result"]["sub_addr"];
	} catch (json::exception &ex) {
		std::cerr << __func__ << ":" << ex.what() << std::endl;
		if (result) free(result);
		assert(0);
	}

	return 0;
}

int bonfire_publish(struct bonfire *bf, const char *topic, const char *content)
{
	if (bf->fwd_sub_addr.empty() && get_forwarder_info(bf))
		return BONFIRE_PUBLISH_FAILED;

	if (bf->pub == NULL) {
		bf->pub = spdnet_node_new(bf->ctx, SPDNET_PUB);
		spdnet_connect(bf->pub, bf->fwd_sub_addr.c_str());
		sleep(1);
	}
	assert(bf->pub);

	struct spdnet_msg msg;
	SPDNET_MSG_INIT_DATA(&msg, topic, NULL, content);
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
		return BONFIRE_SUBSCRIBE_FAILED;

	if (bf->subs.find(topic) != bf->subs.end())
		return BONFIRE_SUBSCRIBE_EXIST;

	void *sub = spdnet_node_new(bf->ctx, SPDNET_SUB);
	spdnet_nodepool_add(bf->snodepool, sub);
	spdnet_connect(sub, bf->fwd_pub_addr.c_str());
	spdnet_set_filter(sub, topic, strlen(topic));

	subscribe_struct *ss = (subscribe_struct *)malloc(sizeof(*ss));
	ss->cb = cb;
	ss->arg = arg;
	spdnet_set_user_data(sub, ss);
	spdnet_recvmsg_async(sub, subscribe_cb, NULL, 0);

	bf->subs.insert(std::make_pair(topic, sub));
	return 0;
}

int bonfire_unsubscribe(struct bonfire *bf, const char *topic)
{
	auto it = bf->subs.find(topic);
	if (it == bf->subs.end())
		return BONFIRE_SUBSCRIBE_NONEXIST;

	spdnet_nodepool_del(bf->snodepool, it->second);
	free(spdnet_get_user_data(it->second));
	assert(spdnet_node_destroy(it->second) == 0);
	bf->subs.erase(it);

	return 0;
}

/*
 * bonfire broker
 */

#define SERVICE_ERRNO_MAP(XX) \
	XX(EOK, "OK") \
	XX(EINVAL, "Invalid argument") \
	XX(EEXIST, "Item exists") \
	XX(ENONEXIST, "Item not exists") \
	XX(EPERM, "Permission deny")

typedef enum {
#define XX(code, _) SERVICE_##code,
	SERVICE_ERRNO_MAP(XX)
#undef XX
	SERVICE_ERRNO_MAX = 1000
} service_errno_t;

#define SERVICE_STRERROR_GEN(name, msg) case SERVICE_ ## name: return msg;
const char *service_strerror(int err) {
	switch (err) {
		SERVICE_ERRNO_MAP(SERVICE_STRERROR_GEN)
	default:
			return "Unknown errno";
	}
}
#undef SERVICE_STRERROR_GEN

struct bonfire_broker {
	void *ctx;

	string router_addr;
	string router_id;
	void *router;

	string fwd_pub_addr;
	string fwd_sub_addr;
	void *fwd;

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
		{"errmsg", service_strerror(err)},
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
		std::cerr << __func__ << ":" << ex.what() << std::endl;
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
				pack(bm, SERVICE_EOK, json(it->second));
				return;
			}

			auto lit = bbrk->bf->local_services.find(cnt["header"]);
			if (lit != bbrk->bf->local_services.end()) {
				pack(bm, SERVICE_EOK, json(lit->second));
				return;
			}

			pack(bm, SERVICE_ENONEXIST, nullptr);
			return;
		}
	} catch (json::exception &ex) {
		std::cerr << __func__ << ":" << ex.what() << std::endl;
		pack(bm, SERVICE_EINVAL, nullptr);
		return;
	}

	json cnt = json::array();
	int i = 0;

	for (auto &item : bbrk->bf->local_services)
		cnt[i++] = item.second;

	for (auto &item : bbrk->bf->services)
		cnt[i++] = item.second;

	pack(bm, SERVICE_EOK, cnt);
}

static void on_service_add(struct bmsg *bm)
{
	struct bonfire_broker *bbrk = (struct bonfire_broker *)
		bonfire_get_user_data(bmsg_get_bonfire(bm));
	struct bonfire_service bs;

	try {
		bs = unpack(&bm->request);
	} catch (json::exception &ex) {
		std::cerr << __func__ << ":" << ex.what() << std::endl;
		pack(bm, SERVICE_EINVAL, nullptr);
		return;
	}

	if (bbrk->bf->services.find(bs.header) !=
	    bbrk->bf->services.end()) {
		pack(bm, SERVICE_EEXIST, nullptr);
		return;
	}

	bbrk->bf->services.insert(std::make_pair(bs.header, bs));
	save_cache(bbrk);
	pack(bm, SERVICE_EOK, nullptr);
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
		std::cerr << __func__ << ":" << ex.what() << std::endl;
		pack(bm, SERVICE_EINVAL, nullptr);
		return;
	}

	auto it = bbrk->bf->services.find(header);
	if (it == bbrk->bf->services.end()) {
		pack(bm, SERVICE_ENONEXIST, nullptr);
		return;
	}

	bbrk->bf->services.erase(it);
	save_cache(bbrk);
	pack(bm, SERVICE_EOK, nullptr);
}

static void on_forwarder_info(struct bmsg *bm)
{
	struct bonfire_broker *bbrk = (struct bonfire_broker *)
		bonfire_get_user_data(bmsg_get_bonfire(bm));

	json cnt = {
		{"pub_addr", bbrk->fwd_pub_addr},
		{"sub_addr", bbrk->fwd_sub_addr},
	};

	pack(bm, SERVICE_EOK, cnt);
}

struct bonfire_broker *bonfire_broker_new(const char *listen_addr,
                                          const char *listen_id,
                                          const char *pub_addr,
                                          const char *sub_addr)
{
	struct bonfire_broker *bbrk = new struct bonfire_broker;
	assert(strlen(listen_addr) < SPDNET_ADDRESS_SIZE);
	assert(strlen(listen_id) < SPDNET_SOCKID_SIZE);

	// ctx
	bbrk->ctx = spdnet_ctx_new();
	assert(bbrk->ctx);

	// router
	bbrk->router_addr = listen_addr;
	bbrk->router_id = string("bonfire-router-") + listen_id;
	bbrk->router = spdnet_router_new(
		bbrk->ctx, bbrk->router_id.c_str());
	assert(bbrk->router);
	assert(spdnet_router_bind(bbrk->router, listen_addr) == 0);

	// forwarder
	bbrk->fwd_pub_addr = pub_addr;
	bbrk->fwd_sub_addr = sub_addr;
	bbrk->fwd = spdnet_forwarder_new(bbrk->ctx);
	assert(spdnet_forwarder_bind(bbrk->fwd, pub_addr, sub_addr) == 0);

	// bonfire cli
	bbrk->bf = bonfire_new(listen_addr, listen_id, listen_id);
	assert(bbrk->bf);
	bonfire_set_user_data(bbrk->bf, bbrk);
	bonfire_add_service(bbrk->bf, BONFIRE_SERVICE_INFO, on_service_info);
	bonfire_add_service(bbrk->bf, BONFIRE_SERVICE_ADD, on_service_add);
	bonfire_add_service(bbrk->bf, BONFIRE_SERVICE_DEL, on_service_del);
	bonfire_add_service(bbrk->bf, BONFIRE_FORWARDER_INFO,
	                    on_forwarder_info);

	return bbrk;
}

void bonfire_broker_destroy(struct bonfire_broker *bbrk)
{
	bonfire_destroy(bbrk->bf);
	spdnet_forwarder_destroy(bbrk->fwd);
	spdnet_router_destroy(bbrk->router);
	spdnet_ctx_destroy(bbrk->ctx);

	delete bbrk;
}

int bonfire_broker_loop(struct bonfire_broker *bbrk, long timeout)
{
	spdnet_router_loop(bbrk->router, timeout);
	spdnet_forwarder_loop(bbrk->fwd, 0);
	bonfire_loop(bbrk->bf, 0);
	return 0;
}

void bonfire_broker_set_gateway(struct bonfire_broker *bbrk,
                                const char *gateway_addr)
{
	char gateway_id[SPDNET_SOCKID_SIZE];
	size_t gateway_len;

	spdnet_router_associate(bbrk->router,
	                        gateway_addr,
	                        gateway_id,
	                        &gateway_len);
	spdnet_router_set_gateway(bbrk->router, gateway_id, gateway_len);
}

void bonfire_broker_set_cache_file(struct bonfire_broker *bbrk,
                                   const char *cache_file)
{
	bbrk->cache_file = cache_file;
	load_cache(bbrk);
}
