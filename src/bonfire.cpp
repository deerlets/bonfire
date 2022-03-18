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

static void handle_msg(struct bonfire *bf, struct bmsg *bm)
{
    string header((char *)MSG_HEADER_DATA(&bm->request),
                  MSG_HEADER_SIZE(&bm->request));

    auto it = bf->services.find(header);
    if (it == bf->services.end() || !it->second) {
        bmsg_filtered(bm);
        return;
    }

    // call handler
    it->second(bm);
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

static void recvmsg_cb(
    struct spdnet_node *snode, struct spdnet_msg *msg, void *arg, int flag)
{
    if (flag) {
        fprintf(stderr, "[%s]: flag => %d\n", __func__, flag);
        return;
    }
    assert(msg);

    struct bonfire *bf = (struct bonfire *)arg;
    struct bmsg *bm = bmsg_new();

    // response
    string resp_header((char *)MSG_HEADER_DATA(msg), MSG_HEADER_SIZE(msg));
    resp_header += BONFIRE_RESPONSE_SUBFIX;
    spdnet_msg_close(&bm->response);
    spdnet_msg_init_data(
        &bm->response,
        MSG_SRCID_DATA(msg),
        MSG_SRCID_SIZE(msg),
        resp_header.c_str(),
        resp_header.size(),
        NULL, 0);

    // request
    spdnet_msg_move(&bm->request, msg);

    // bonfire
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

    // ctx
    bf->ctx = spdnet_ctx_new();
    assert(bf->ctx);

    // snode
    bf->snode = spdnet_node_new(bf->ctx, SPDNET_DEALER);
    assert(bf->snode);

    // timeout
    bf->timeout = BONFIRE_DEFAULT_TIMEOUT;

    // services
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

    // pub
    bf->pub = NULL;
    pthread_mutex_init(&bf->subs_lock, NULL);

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

    for (auto it = bf->bmsgs.begin(); it != bf->bmsgs.end();) {
        bmsg_destroy(*it);
    }
    bf->bmsgs.clear();

    delete bf;
}

int bonfire_connect(struct bonfire *bf, const char *broker_addr)
{
    assert(strlen(broker_addr) < SPDNET_ADDR_SIZE);
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

void *bonfire_get_user_data(struct bonfire *bf)
{
    return bf->user_data;
}

void bonfire_set_user_data(struct bonfire *bf, void *data)
{
    bf->user_data = data;
}

/*
 * services
 */

static int servcall(
    struct bonfire *bf, const char *header, const char *content, char **result)
{
    struct spdnet_node *snode = spdnet_node_new(bf->ctx, SPDNET_DEALER);
    assert(spdnet_connect(snode, bf->broker_address.c_str()) == 0);

    struct spdnet_msg tmp;
    SPDNET_MSG_INIT_DATA(&tmp, BONFIRE_BROKER, header, content);
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

int bonfire_add_service(
    struct bonfire *bf, const char *header, bonfire_service_cb handler)
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
        .sockid = spdnet_get_id(bf->snode),
    };

    char *result = NULL;
    if (servcall(bf, BONFIRE_SERVICE_ADD, json(bs).dump().c_str(), &result))
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
        fprintf(stderr, "[%s]: %s\n", __func__, ex.what());
        assert(0);
    }

    pthread_mutex_lock(&bf->services_lock);
    bf->services.insert(std::make_pair(header, handler));
    pthread_mutex_unlock(&bf->services_lock);
    return 0;
}

int bonfire_del_service(struct bonfire *bf, const char *header)
{
    pthread_mutex_lock(&bf->services_lock);
    if (bf->services.find(header) == bf->services.end()) {
        pthread_mutex_unlock(&bf->services_lock);
        errno = BONFIRE_ENOSERV;
        return -1;
    }
    pthread_mutex_unlock(&bf->services_lock);

    json cnt = {{"header", header}};
    char *result = NULL;
    if (servcall(bf, BONFIRE_SERVICE_DEL, cnt.dump().c_str(), &result))
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
        fprintf(stderr, "[%s]: %s\n", __func__, ex.what());
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

int bonfire_servcall(
    struct bonfire *bf, const char *header, const char *content, char **result)
{
    json cnt;
    cnt["header"] = header;
    if (content == NULL)
        cnt["content"] = nullptr;
    else
        cnt["content"] = content;
    char *__result = NULL;

    if (servcall(bf, BONFIRE_SERVICE_CALL, cnt.dump().c_str(), &__result))
        return -1;

    try {
        json j = json::parse(__result);
        free(__result);
        __result = NULL;
        if (j["errno"] != 0) {
            errno = j["errno"];
            return -1;
        }
        if (result) {
            string tmp = j["result"]["content"];
            *result = strdup(tmp.c_str());
        }
    } catch (json::exception &ex) {
        fprintf(stderr, "[%s]: %s\n", __func__, ex.what());
        assert(0);
    }

    return 0;
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

static void servcall_cb(
    struct spdnet_node *snode, struct spdnet_msg *msg, void *arg, int flag)
{
    servcall_struct *as = static_cast<servcall_struct *>(arg);

    if (flag) {
        as->cb(as->bf, NULL, 0, as->arg, BONFIRE_ETIMEOUT);
    } else {
        try {
            json j = unpack(msg);
            int err = j["errno"];
            if (err != 0) {
                as->cb(as->bf, NULL, 0, as->arg, err);
            } else {
                string result = j["result"]["content"];
                as->cb(as->bf, result.c_str(), result.size(),
                       as->arg, BONFIRE_EOK);
            }
        } catch (json::exception &ex) {
            fprintf(stderr, "[%s]: %s\n", __func__, ex.what());
            assert(0);
        }
    }

    delete as;
    spdnet_node_destroy(snode);
}

void bonfire_servcall_async(
    struct bonfire *bf, const char *header, const char *content,
    bonfire_servcall_cb cb, void *arg)
{
    struct spdnet_node *snode = spdnet_node_new(bf->ctx, SPDNET_DEALER);
    assert(spdnet_connect(snode, bf->broker_address.c_str()) == 0);

    json j;
    j["header"] = header;
    j["content"] = content;

    struct spdnet_msg tmp;
    SPDNET_MSG_INIT_DATA(&tmp, BONFIRE_BROKER,
                         BONFIRE_SERVICE_CALL, j.dump().c_str());
    assert(spdnet_sendmsg(snode, &tmp) == 0);
    spdnet_msg_close(&tmp);

    servcall_struct *as = new servcall_struct(bf, cb, arg);
    spdnet_recvmsg_async(snode, servcall_cb, as, bf->timeout);
}

/*
 * pubsub
 */

struct subscribe_struct {
    struct bonfire *bf;
    bonfire_subscribe_cb cb;
    void *arg;
};

static void subscribe_cb(
    struct spdnet_node *snode, struct spdnet_msg *msg, void *arg, int flag)
{
    subscribe_struct *ss = static_cast<subscribe_struct *>(
        spdnet_get_user_data(snode));
    assert(flag == 0);
    assert(msg);
    ss->cb(ss->bf,
           MSG_CONTENT_DATA(msg),
           MSG_CONTENT_SIZE(msg),
           ss->arg,
           BONFIRE_EOK);
    spdnet_recvmsg_async(snode, subscribe_cb, NULL, 0);
}

static int get_forwarder_info(struct bonfire *bf)
{
    char *result = NULL;

    if (servcall(bf, BONFIRE_FORWARDER_INFO, NULL, &result))
        return -1;

    try {
        json j = json::parse(result);
        free(result);
        result = NULL;

        assert(j["errno"] == 0);
        bf->fwd_pub_addr = j["result"]["pub_addr"];
        bf->fwd_sub_addr = j["result"]["sub_addr"];
        if (bf->fwd_pub_addr.empty() || bf->fwd_sub_addr.empty())
            return -1;
    } catch (json::exception &ex) {
        fprintf(stderr, "[%s]: %s\n", __func__, ex.what());
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

int bonfire_subscribe(
    struct bonfire *bf, const char *topic, bonfire_subscribe_cb cb, void *arg)
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
        errno = BONFIRE_ENOTOPIC;
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
