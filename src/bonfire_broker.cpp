#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <spdnet.h>

#include <fstream>
#include <iomanip>

#include "bonfire-inl.h"

typedef int (*bonfire_broker_filter)(struct bmsg *bm);

struct bonfire_broker {
	struct spdnet_ctx *ctx;

	string router_addr;
	struct spdnet_node *router;
	bonfire_broker_filter filter;

	string fwd_pub_addr;
	string fwd_sub_addr;
	struct spdnet_forwarder *fwd;

	struct bonfire *bf;

	// global services
	std::map<string, struct bonfire_service> services;

	string cache_file;
};

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
			bbrk->services.insert(
				std::make_pair(bs.header, bs));
		}
	} catch (json::exception &ex) {
		fprintf(stderr, "[%s]: %s\n", __func__, ex.what());
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

	for (auto &item : bbrk->services)
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
			auto it = bbrk->services.find(cnt["header"]);
			if (it != bbrk->services.end()) {
				pack(bm, BONFIRE_EOK, json(it->second));
				return;
			}

			pack(bm, BONFIRE_ENOSERV, nullptr);
			return;
		}
	} catch (json::exception &ex) {
		fprintf(stderr, "[%s]: %s\n", __func__, ex.what());
		pack(bm, BONFIRE_EINVAL, nullptr);
		return;
	}

	json cnt = json::array();
	int i = 0;

	for (auto &item : bbrk->services)
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
		fprintf(stderr, "[%s]: %s\n", __func__, ex.what());
		pack(bm, BONFIRE_EINVAL, nullptr);
		return;
	}

	if (bbrk->services.find(bs.header) !=
	    bbrk->services.end()) {
		auto it = bbrk->services.find(bs.header);
		fprintf(stderr, "[%s]: old_sockid => %s, new_sockid => %s\n",
		        __func__, it->second.sockid.c_str(), bs.sockid.c_str());
		bbrk->services.erase(it);
		//pack(bm, BONFIRE_EEXIST, nullptr);
		//return;
	}

	bbrk->services.insert(std::make_pair(bs.header, bs));
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
		fprintf(stderr, "[%s]: %s\n", __func__, ex.what());
		pack(bm, BONFIRE_EINVAL, nullptr);
		return;
	}

	auto it = bbrk->services.find(header);
	if (it == bbrk->services.end()) {
		pack(bm, BONFIRE_ENOSERV, nullptr);
		return;
	}

	bbrk->services.erase(it);
	save_cache(bbrk);
	pack(bm, BONFIRE_EOK, nullptr);
}

static void __servcall_cb(struct spdnet_node *snode,
                          struct spdnet_msg *msg,
                          void *arg, int flag)
{
	struct bmsg *bm = (struct bmsg *)arg;

	if (flag) {
		pack(bm, BONFIRE_ETIMEOUT, nullptr);
	} else {
		json j;
		j["header"] = string((char *)MSG_HEADER_DATA(msg),
		                     MSG_HEADER_SIZE(msg));
		j["content"] = string((char *)MSG_CONTENT_DATA(msg),
		                      MSG_CONTENT_SIZE(msg));
		pack(bm, BONFIRE_EOK, j);
	}

	bmsg_handled(bm);
	spdnet_node_destroy(snode);
}

static void on_service_call(struct bmsg *bm)
{
	struct bonfire_broker *bbrk = (struct bonfire_broker *)
		bonfire_get_user_data(bmsg_get_bonfire(bm));
	string header;
	string content;

	try {
		json cnt = unpack(&bm->request);
		header = cnt["header"];
		content = cnt["content"];
	} catch (json::exception &ex) {
		fprintf(stderr, "[%s]: %s\n", __func__, ex.what());
		pack(bm, BONFIRE_EINVAL, nullptr);
		return;
	}

	auto it = bbrk->services.find(header);
	if (it == bbrk->services.end()) {
		pack(bm, BONFIRE_ENOSERV, nullptr);
		return;
	}

	struct spdnet_node *snode = spdnet_node_new(bbrk->ctx, SPDNET_DEALER);
	assert(spdnet_connect(snode, bbrk->router_addr.c_str()) == 0);
	struct spdnet_msg tmp;
	SPDNET_MSG_INIT_DATA(&tmp, it->second.sockid.c_str(),
	                     header.c_str(), content.c_str());
	assert(spdnet_sendmsg(snode, &tmp) == 0);
	spdnet_msg_close(&tmp);
	spdnet_recvmsg_async(snode, __servcall_cb, bm, BONFIRE_DEFAULT_TIMEOUT);

	bmsg_pending(bm);
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
		fprintf(stderr, "[%s]: %s(%d)\n", __func__,
		        spdnet_strerror(flag), flag);
		spdnet_recvmsg_async(snode, router_recvmsg_cb, arg, 0);
		return;
	}
	assert(msg);

	// filter register & unregister & alive msg
	if (memcmp(MSG_HEADER_DATA(msg), SPDNET_REGISTER_MSG,
	           strlen(SPDNET_REGISTER_MSG)) == 0 ||
	    memcmp(MSG_HEADER_DATA(msg), SPDNET_UNREGISTER_MSG,
	           strlen(SPDNET_UNREGISTER_MSG)) == 0 ||
	    memcmp(MSG_HEADER_DATA(msg), SPDNET_ALIVE_MSG,
	           strlen(SPDNET_ALIVE_MSG)) == 0 ||
	    memcmp(MSG_HEADER_DATA(msg), BONFIRE_SERVICE_INFO,
	           strlen(BONFIRE_SERVICE_INFO)) == 0 ||
	    memcmp(MSG_HEADER_DATA(msg), BONFIRE_SERVICE_ADD,
	           strlen(BONFIRE_SERVICE_ADD)) == 0 ||
	    memcmp(MSG_HEADER_DATA(msg), BONFIRE_SERVICE_DEL,
	           strlen(BONFIRE_SERVICE_DEL)) == 0 ||
	    memcmp(MSG_HEADER_DATA(msg), BONFIRE_SERVICE_CALL,
	           strlen(BONFIRE_SERVICE_CALL)) == 0 ||
	    memcmp(MSG_HEADER_DATA(msg), BONFIRE_FORWARDER_INFO,
	           strlen(BONFIRE_FORWARDER_INFO)) == 0) {
		spdnet_builtin_router_recvmsg_cb(snode, msg, arg, flag);
		spdnet_recvmsg_async(snode, router_recvmsg_cb, arg, 0);
		return;
	}

	struct bonfire_broker *bbrk =
		(struct bonfire_broker *)spdnet_get_user_data(snode);
	if (bbrk->filter) {
		struct bmsg *bm = bmsg_new();
		spdnet_msg_copy(&bm->request, msg);
		if (bbrk->filter(bm) && MSG_CONTENT_SIZE(&bm->response)) {
			string resp_header((char *)MSG_HEADER_DATA(msg),
			                   MSG_HEADER_SIZE(msg));
			resp_header += BONFIRE_RESPONSE_SUBFIX;
			struct spdnet_msg tmp;
			spdnet_msg_init_data(&tmp,
			                     MSG_SRCID_DATA(msg),
			                     MSG_SRCID_SIZE(msg),
			                     resp_header.c_str(),
			                     resp_header.size(),
			                     MSG_CONTENT_DATA(&bm->response),
			                     MSG_CONTENT_SIZE(&bm->response));
			spdnet_sendmsg(snode, &tmp);
			spdnet_msg_close(&tmp);
			bmsg_destroy(bm);
			spdnet_recvmsg_async(snode, router_recvmsg_cb, arg, 0);
			return;
		}
		bmsg_destroy(bm);
	}

	spdnet_builtin_router_recvmsg_cb(snode, msg, arg, flag);
	spdnet_recvmsg_async(snode, router_recvmsg_cb, arg, 0);
}

struct bonfire_broker *bonfire_broker_new(const char *listen_addr,
                                          const char *pub_addr,
                                          const char *sub_addr)
{
	struct bonfire_broker *bbrk = new struct bonfire_broker;
	assert(strlen(listen_addr) < SPDNET_ADDR_SIZE);

	// ctx
	bbrk->bf = bonfire_new();
	bbrk->ctx = bbrk->bf->ctx;

	// router
	bbrk->router_addr = listen_addr;
	bbrk->router = spdnet_node_new(bbrk->ctx, SPDNET_ROUTER);
	assert(spdnet_bind(bbrk->router, listen_addr) == 0);
	spdnet_recvmsg_async(bbrk->router, router_recvmsg_cb, NULL, 0);
	spdnet_set_user_data(bbrk->router, bbrk);
	bbrk->filter = NULL;

	// forwarder
	bbrk->fwd_pub_addr = pub_addr;
	bbrk->fwd_sub_addr = sub_addr;
	bbrk->fwd = spdnet_forwarder_new(bbrk->ctx);
	assert(spdnet_forwarder_bind(bbrk->fwd, pub_addr, sub_addr) == 0);

	// bonfire
	spdnet_set_id(bbrk->bf->snode, BONFIRE_BROKER_SOCKID);
	bonfire_set_user_data(bbrk->bf, bbrk);
	bonfire_connect(bbrk->bf, listen_addr);

	bbrk->bf->services.insert(
		std::make_pair(BONFIRE_SERVICE_INFO, on_service_info));
	bbrk->bf->services.insert(
		std::make_pair(BONFIRE_SERVICE_ADD, on_service_add));
	bbrk->bf->services.insert(
		std::make_pair(BONFIRE_SERVICE_DEL, on_service_del));
	bbrk->bf->services.insert(
		std::make_pair(BONFIRE_SERVICE_CALL, on_service_call));
	bbrk->bf->services.insert(
		std::make_pair(BONFIRE_FORWARDER_INFO, on_forwarder_info));

	return bbrk;
}

void bonfire_broker_destroy(struct bonfire_broker *bbrk)
{
	spdnet_forwarder_destroy(bbrk->fwd);
	spdnet_node_destroy(bbrk->router);
	bonfire_destroy(bbrk->bf); // bbrk->bf->ctx must be fini at last

	delete bbrk;
}

int bonfire_broker_loop(struct bonfire_broker *bbrk, long timeout)
{
	bonfire_loop(bbrk->bf, timeout);
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
	char gateway_id[SPDNET_ID_SIZE];
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
