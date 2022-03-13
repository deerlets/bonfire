#ifndef __BONFIRE_BONFIRE_INL_H
#define __BONFIRE_BONFIRE_INL_H

#include <spdnet.h>
#include "bonfire.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * bmsg
 */

enum bmsg_lifetime_state {
	// raw
	BM_RAW = 0,

	// intermediate
	BM_PENDING = 0x10,

	// result
	BM_FILTERED = 0x20,
	BM_HANDLED,
};

struct bmsg {
	// sockid of request should be dstid after init before using
	struct spdnet_msg request;

	// sockid of response should be srcid after init before using
	struct spdnet_msg response;

	// bonfire cli
	struct bonfire *bf;

	// lifetime state
	int state;

	// bonfire never touch user_data
	void *user_data;
};

struct bmsg *bmsg_new();
void bmsg_destroy(struct bmsg *bm);
#ifdef __cplusplus
}
#endif

/*
 * C++ header
 */

#include <string>
#include <list>
#include <map>
#include <nlohmann/json.hpp>
using string =std::string;
using json = nlohmann::json;

#define BONFIRE_BROKER_SOCKID "bonfire-broker-sockid"
#define BONFIRE_SERVICE_INFO "bonfire://service/info"
#define BONFIRE_SERVICE_ADD "bonfire://service/add"
#define BONFIRE_SERVICE_DEL "bonfire://service/del"
#define BONFIRE_SERVICE_CALL "bonfire://service/call"
#define BONFIRE_FORWARDER_INFO "bonfire://forwarder/info"
#define BONFIRE_RESPONSE_SUBFIX "#reply"

/*
 * bonfire err
 */

#define BONFIRE_STRERROR_GEN(name, msg) case BONFIRE_ ## name: return msg;
static inline const char *bonfire_strerror(int err) {
	switch (err) {
		BONFIRE_ERRNO_MAP(BONFIRE_STRERROR_GEN)
	default:
		return "Unknown errno";
	}
}
#undef BONFIRE_STRERROR_GEN

/*
 * bonfire utils
 */

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

/*
 * bonfire service
 */

struct bonfire_service {
	string header;
	string sockid;
};

static inline void to_json(json &j, const struct bonfire_service &bs)
{
	j["header"] = bs.header;
	j["sockid"] = bs.sockid;
}

static inline void from_json(const json &j, bonfire_service &bs)
{
	j.at("header").get_to(bs.header);
	j.at("sockid").get_to(bs.sockid);
}

/*
 * bonfire
 */

struct bonfire {
	string broker_address;

	struct spdnet_ctx *ctx;
	struct spdnet_node *snode; // for local services

	string fwd_pub_addr;
	string fwd_sub_addr;
	struct spdnet_node *pub;
	std::map<string, struct spdnet_node *> subs;
	pthread_mutex_t subs_lock;

	long timeout;

	// services
	std::map<string, bonfire_service_cb> services;
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

#endif
