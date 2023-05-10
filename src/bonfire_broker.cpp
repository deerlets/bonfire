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
    // ctx
    struct spdnet_ctx *ctx;

    // router
    string router_addr;
    struct spdnet_node *router;
    bonfire_broker_filter filter;

    // inner bf
    struct bonfire *bf;

    // services
    std::map<string, struct bonfire_service> services;
    string cache_file;

    // forwarder
    string fwd_pub_addr;
    string fwd_sub_addr;
    struct spdnet_forwarder *fwd;
};

static void load_cache(struct bonfire_broker *brk)
{
    if (brk->cache_file.empty())
        return;

    if (access(brk->cache_file.c_str(), F_OK) != 0)
        return;

    std::ifstream ifs(brk->cache_file);

    try {
        json j = json::parse(ifs);
        for (auto it = j["services"].begin();
             it != j["services"].end(); ++it) {
            struct bonfire_service bs = *it;
            brk->services.insert(std::make_pair(bs.header, bs));
        }
    } catch (json::exception &ex) {
        fprintf(stderr, "[%s]: %s\n", __func__, ex.what());
    }

    ifs.close();
}

static void save_cache(struct bonfire_broker *brk)
{
    if (brk->cache_file.empty())
        return;

    std::ofstream ofs(brk->cache_file);

    json cnt = {{"services", json::array()}};
    int i = 0;

    for (auto &item : brk->services)
        cnt["services"][i++] = item.second;

    ofs << std::setw(4) << cnt << std::endl;
    ofs.close();
}

static void at_service_info(struct bmsg *bm)
{
    struct bonfire_broker *brk = (struct bonfire_broker *)
        bonfire_get_user_data(bmsg_get_bonfire(bm));

    try {
        json cnt;
        if (MSG_CONTENT_SIZE(&bm->request))
            cnt = unpack(&bm->request);
        if (cnt.find("header") != cnt.end()) {
            auto it = brk->services.find(cnt["header"]);
            if (it != brk->services.end()) {
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

    for (auto &item : brk->services)
        cnt[i++] = item.second;

    pack(bm, BONFIRE_EOK, cnt);
}

static void at_service_add(struct bmsg *bm)
{
    struct bonfire_broker *brk = (struct bonfire_broker *)
        bonfire_get_user_data(bmsg_get_bonfire(bm));
    struct bonfire_service bs;

    try {
        bs = unpack(&bm->request);
    } catch (json::exception &ex) {
        fprintf(stderr, "[%s]: %s\n", __func__, ex.what());
        pack(bm, BONFIRE_EINVAL, nullptr);
        return;
    }

    if (brk->services.find(bs.header) !=
        brk->services.end()) {
        auto it = brk->services.find(bs.header);
        fprintf(stderr, "[%s]: service sockid changed, old => %s, new => %s\n",
                __func__, it->second.sockid.c_str(), bs.sockid.c_str());
        brk->services.erase(it);
        //pack(bm, BONFIRE_EEXIST, nullptr);
        //return;
    }

    //fprintf(stdout, "[%s]: header => %s\n", __func__, bs.header.c_str());
    brk->services.insert(std::make_pair(bs.header, bs));
    save_cache(brk);
    pack(bm, BONFIRE_EOK, nullptr);
}

static void at_service_del(struct bmsg *bm)
{
    struct bonfire_broker *brk = (struct bonfire_broker *)
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

    auto it = brk->services.find(header);
    if (it == brk->services.end()) {
        pack(bm, BONFIRE_ENOSERV, nullptr);
        return;
    }

    //fprintf(stdout, "[%s]: header => %s\n", __func__, header.c_str());
    brk->services.erase(it);
    save_cache(brk);
    pack(bm, BONFIRE_EOK, nullptr);
}

static void __servcall_cb(struct spdnet_node *snode, struct spdnet_msg *msg,
                          void *arg, int flag)
{
    struct bmsg *bm = (struct bmsg *)arg;

    if (flag) {
        pack(bm, BONFIRE_ETIMEOUT, nullptr);
    } else {
        json j;
        j["header"] = string(
            (char *)MSG_HEADER_DATA(msg), MSG_HEADER_SIZE(msg));
        j["content"] = string(
            (char *)MSG_CONTENT_DATA(msg), MSG_CONTENT_SIZE(msg));
        pack(bm, BONFIRE_EOK, j);
    }

    bmsg_handled(bm);
    spdnet_node_destroy(snode);
}

static void at_service_call(struct bmsg *bm)
{
    struct bonfire_broker *brk = (struct bonfire_broker *)
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

    auto it = brk->services.find(header);
    if (it == brk->services.end()) {
        pack(bm, BONFIRE_ENOSERV, nullptr);
        return;
    }

    //fprintf(stdout, "[%s]: %s\n", __func__, header.c_str());
    struct spdnet_node *snode = spdnet_node_new(brk->ctx, SPDNET_DEALER);
    assert(spdnet_connect(snode, brk->router_addr.c_str()) == 0);
    struct spdnet_msg tmp;
    SPDNET_MSG_INIT_DATA(
        &tmp, it->second.sockid.c_str(), header.c_str(), content.c_str());
    assert(spdnet_sendmsg(snode, &tmp) == 0);
    spdnet_msg_close(&tmp);
    spdnet_recvmsg_async(snode, __servcall_cb, bm, BONFIRE_DEFAULT_TIMEOUT);

    bmsg_pending(bm);
}

static void at_forwarder_info(struct bmsg *bm)
{
    struct bonfire_broker *brk = (struct bonfire_broker *)
        bonfire_get_user_data(bmsg_get_bonfire(bm));

    json cnt = {
        {"pub_addr", brk->fwd_pub_addr},
        {"sub_addr", brk->fwd_sub_addr},
    };

    pack(bm, BONFIRE_EOK, cnt);
}

static void router_recvmsg_cb(struct spdnet_node *snode, struct spdnet_msg *msg,
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
    if (memcmp(MSG_HEADER_DATA(msg), SPDNET_REGISTER_HDR,
               strlen(SPDNET_REGISTER_HDR)) == 0 ||
        memcmp(MSG_HEADER_DATA(msg), SPDNET_UNREGISTER_HDR,
               strlen(SPDNET_UNREGISTER_HDR)) == 0 ||
        memcmp(MSG_HEADER_DATA(msg), SPDNET_ALIVE_HDR,
               strlen(SPDNET_ALIVE_HDR)) == 0 ||
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

    struct bonfire_broker *brk =
        (struct bonfire_broker *)spdnet_get_user_data(snode);
    if (brk->filter) {
        struct bmsg *bm = bmsg_new();
        spdnet_msg_copy(&bm->request, msg);
        if (brk->filter(bm) && MSG_CONTENT_SIZE(&bm->response)) {
            string resp_header(
                (char *)MSG_HEADER_DATA(msg), MSG_HEADER_SIZE(msg));
            resp_header += BONFIRE_RESPONSE_SUBFIX;
            struct spdnet_msg tmp;
            spdnet_msg_init_data(
                &tmp,
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

struct bonfire_broker *bonfire_broker_new(const char *listen_addr)
{
    struct bonfire_broker *brk = new struct bonfire_broker;
    assert(strlen(listen_addr) < SPDNET_ADDR_SIZE);

    // ctx
    brk->bf = bonfire_new();
    brk->ctx = brk->bf->ctx;

    // router
    brk->router_addr = listen_addr;
    brk->router = spdnet_node_new(brk->ctx, SPDNET_ROUTER);
    assert(spdnet_bind(brk->router, listen_addr) == 0);
    spdnet_recvmsg_async(brk->router, router_recvmsg_cb, NULL, 0);
    spdnet_set_user_data(brk->router, brk);
    brk->filter = NULL;

    // bonfire
    spdnet_set_id(brk->bf->snode, BONFIRE_BROKER);
    bonfire_set_user_data(brk->bf, brk);
    bonfire_connect(brk->bf, listen_addr);

    // services
    brk->bf->services.insert(
        std::make_pair(BONFIRE_SERVICE_INFO, at_service_info));
    brk->bf->services.insert(
        std::make_pair(BONFIRE_SERVICE_ADD, at_service_add));
    brk->bf->services.insert(
        std::make_pair(BONFIRE_SERVICE_DEL, at_service_del));
    brk->bf->services.insert(
        std::make_pair(BONFIRE_SERVICE_CALL, at_service_call));
    brk->bf->services.insert(
        std::make_pair(BONFIRE_FORWARDER_INFO, at_forwarder_info));

    // forwarder
    brk->fwd = NULL;

    return brk;
}

void bonfire_broker_destroy(struct bonfire_broker *brk)
{
    if (brk->fwd)
        spdnet_forwarder_destroy(brk->fwd);
    spdnet_node_destroy(brk->router);
    bonfire_destroy(brk->bf); // brk->bf->ctx must be fini at last
    delete brk;
}

int bonfire_broker_loop(struct bonfire_broker *brk, long timeout)
{
    bonfire_loop(brk->bf, timeout);
    return 0;
}

void bonfire_broker_set_filter(struct bonfire_broker *brk,
                               bonfire_broker_filter_cb cb)
{
    brk->filter = cb;
}

void bonfire_broker_set_gateway(struct bonfire_broker *brk,
                                const char *gateway_addr)
{
    char gateway_id[SPDNET_ID_SIZE];
    size_t gateway_len;

    spdnet_associate(brk->router, gateway_addr, gateway_id, &gateway_len);
    spdnet_set_gateway(brk->router, gateway_id, gateway_len);
}

void bonfire_broker_set_cache_file(struct bonfire_broker *brk,
                                   const char *cache_file)
{
    brk->cache_file = cache_file;
    load_cache(brk);
}

void bonfire_broker_enable_pubsub(struct bonfire_broker *brk,
                                  const char *pub_addr,
                                  const char *sub_addr)
{
    // forwarder
    brk->fwd_pub_addr = pub_addr;
    brk->fwd_sub_addr = sub_addr;
    brk->fwd = spdnet_forwarder_new(brk->ctx);
    assert(spdnet_forwarder_bind(brk->fwd, pub_addr, sub_addr) == 0);
}
