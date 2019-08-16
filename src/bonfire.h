#ifndef __BONFIRE_BONFIRE_H
#define __BONFIRE_BONFIRE_H

#include <spdnet.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * bonfire_msg
 */

#define BONFIRE_RESPONSE_SUBFIX "#reply"
#define BONFIRE_RESPONSE_SUBFIX_LEN (sizeof(BONFIRE_RESPONSE_SUBFIX) - 1)

enum bonfire_msg_lifetime_state {
	// raw
	BM_RAW = 0,

	// intermediate
	BM_PENDING = 0x10,

	// result
	BM_FILTERED = 0x20,
	BM_HANDLED,
};

struct bonfire_msg {
	// sockid of request should be dstid after init before using
	struct spdnet_msg request;

	// sockid of response should be srcid after init before using
	struct spdnet_msg response;

	// bonfire'll init it with msg_arg but never touch it any more
	void *user_arg;

	// bonfire never touch user_data
	void *user_data;

	/* private: used by bonfire cli */

	// request convenient
	const void *header;
	size_t header_len;

	// srcid & dstid
	const void *srcid;
	size_t srcid_len;
	const void *dstid;
	size_t dstid_len;

	// snode which received the request
	void *snode;

	// lifetime state
	int state;
};

void bonfire_msg_init(struct bonfire_msg *bm, struct spdnet_msg *request);
void bonfire_msg_init2(struct bonfire_msg *bm,
                       const char *req_sockid,
                       const char *req_header,
                       const char *req_content);
void bonfire_msg_close(struct bonfire_msg *bm);

void bonfire_msg_pending(struct bonfire_msg *bm);
void bonfire_msg_filtered(struct bonfire_msg *bm);
void bonfire_msg_handled(struct bonfire_msg *bm);

void
bonfire_msg_get_reqid(struct bonfire_msg *bm, const void *sockid, size_t *len);
void
bonfire_msg_write_response(struct bonfire_msg *bm, const void *data, int size);

/*
 * bonfire service
 */

typedef void (*service_handler_func_t)(struct bonfire_msg *bm);

struct bonfire_service_info {
	const char *uri;
	service_handler_func_t handler;
	const char *desc;
};

#define INIT_SERVICE(uri, handler, desc) { uri, handler, desc }

/*
 * bonfire cli
 */

struct bonfire;

struct bonfire *bonfire_new(const char *remote_addr,
                            const char *remote_id,
                            const char *local_id);
void bonfire_destroy(struct bonfire *bf);
void bonfire_loop(struct bonfire *bf, long timeout);

void bonfire_set_msg_arg(struct bonfire *bf, void *arg);

void bonfire_set_msg_prepare(struct bonfire *bf,
                             service_handler_func_t prepare_cb);

void bonfire_set_msg_finished(struct bonfire *bf,
                              service_handler_func_t finished_cb);

void bonfire_set_local_services(struct bonfire *bf,
                                struct bonfire_service_info *services);

#define BONFIRE_SERVCALL_OK 0
#define BONFIRE_SERVCALL_NOSERV 1
#define BONFIRE_SERVCALL_TIMEOUT 2

typedef
void (*bonfire_servcall_cb)(const void *resp, size_t len, void *arg, int flag);

void bonfire_servcall(struct bonfire *bf,
                      const char *header,
                      const char *content,
                      bonfire_servcall_cb cb,
                      void *arg,
                      long timeout);

int bonfire_servcall_sync(struct bonfire *bf,
                          const char *header,
                          const char *content,
                          char **result, // free by user
                          long timeout);

int bonfire_servsync(struct bonfire *bf);

/*
 * bonfire server
 */

struct bonfire_server;

void *bonfire_server_new(const char *listen_addr, const char *local_id);
void bonfire_server_destroy(struct bonfire_server *server);
int bonfire_server_loop(struct bonfire_server *server, long timeout);
void bonfire_server_set_gateway(struct bonfire_server *server,
                                const char *gateway_id);

#ifdef __cplusplus
}
#endif
#endif
