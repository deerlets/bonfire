#ifndef __ZEBRA_SERVICE_H
#define __ZEBRA_SERVICE_H

#include <stddef.h>
#include <pthread.h>
#include <spdnet.h>
#include "list.h"
#include "timer.h"

#define SERVAREA_DELIMITER "://"
#define SERVICE_DELIMITER '?'
#define RESPONSE_SUBFIX "#reply"
#define RESPONSE_SUBFIX_LEN (sizeof(RESPONSE_SUBFIX) - 1)

#ifdef __cplusplus
extern "C" {
#endif

/*
 * service_errno
 */

#define SERVICE_ERRNO_MAP(XX) \
	XX(EOK, "OK") \
	XX(ENOSERV, "No service") \
	XX(ETIMEOUT, "Timeout")

typedef enum {
#define XX(code, _) SERVICE_##code,
	SERVICE_ERRNO_MAP(XX)
#undef XX
	SERVICE_ERRNO_MAX = 1000
} service_errno_t;

const char *service_strerror(int err);

/*
 * servmsg
 */

enum servmsg_lifetime_state {
	// raw
	SM_RAW_UNINTERRUPTIBLE = 0,
	SM_RAW_INTERRUPTIBLE,

	// intermediate
	SM_PENDING = 0x10,

	// result
	SM_FILTERED = 0x20,
	SM_TIMEOUT,
	SM_HANDLED,
};

struct servmsg {
	// sockid of request should be dstid after init before using
	struct spdnet_msg request;

	// sockid of response should be srcid after init before using
	struct spdnet_msg response;

	/* private: used by inner servhub */

	// request convenient
	const void *header;
	size_t header_len;
	const void *area;
	size_t area_len;
	const void *service;
	size_t service_len;

	// srcid & dstid
	const void *srcid;
	size_t srcid_len;
	const void *dstid;
	size_t dstid_len;

	// snode which received the request
	struct spdnet_node *snode;

	// lifetime state
	int state;

	// errno and errmsg returned from handlers
	int err;
	const char *errmsg;

	// msg list for servhub
	struct zebra_list_head node;

	// servhub never touch this filed
	void *user_data;
};

void servmsg_init(struct servmsg *sm, struct spdnet_msg *request);
void servmsg_init2(struct servmsg *sm, const char *req_sockid,
                   const char *req_header, const char *req_content);
void servmsg_close(struct servmsg *sm);

int servmsg_interruptible(struct servmsg *sm);
void servmsg_pending(struct servmsg *sm);
void servmsg_filtered(struct servmsg *sm);
void servmsg_timeout(struct servmsg *sm);
void servmsg_handled(struct servmsg *sm);
void servmsg_set_error(struct servmsg *sm, int err, const char *errmsg);

const char *servmsg_reqid(struct servmsg *sm);
int servmsg_respcnt_reset_data(struct servmsg *sm, const void *data, int size);

/*
 * service
 */

typedef void (*service_handler_func_t)(struct servmsg *sm);

struct service {
	const char *name;
	service_handler_func_t handler;
	const char *desc;
	int visible;
	unsigned int tag;
	struct zebra_hlist_node hash_node;
	struct zebra_list_head node;
};

#define INIT_SERVICE(name, handler, desc) \
	{ name, handler, desc, 1, 0 }
#define INIT_SERVICE_PRIVATE(name, handler, desc) \
	{ name, handler, desc, 0, 0 }

/*
 * servarea
 */

#define SERVAREA_NAME_SIZE 64

struct servarea {
	char name[SERVAREA_NAME_SIZE];
	struct zebra_hlist_head *servtab;
	struct zebra_list_head services;
	struct zebra_list_head node;
};

int servarea_init(struct servarea *sa, const char *name);
int servarea_close(struct servarea *sa);
void servarea_register_service(struct servarea *sa, struct service *service);
void servarea_unregister_service(struct servarea *sa, struct service *service);
void servarea_register_services(struct servarea *sa, struct service *services);
struct service *
__servarea_find_service(struct servarea *sa, const char *name);
struct service *
servarea_find_service(struct servarea *sa, const char *name, size_t len);
service_handler_func_t
__servarea_find_handler(struct servarea *sa, const char *name);
service_handler_func_t
servarea_find_handler(struct servarea *sa, const char *name, size_t len);

/*
 * servhub
 */

struct servhub {
	char id[SPDNET_SOCKID_SIZE];
	char router_addr[SPDNET_ADDRESS_SIZE];

	struct spdnet_nodepool *snodepool;
	// default snode used by servhub
	struct spdnet_node *snode;

	service_handler_func_t prepare_cb;
	service_handler_func_t finished_cb;

	struct zebra_list_head servareas;
	pthread_mutex_t servareas_lock;

	struct zebra_list_head servmsgs;
	int servmsg_total;
	int servmsg_doing;
	int servmsg_filtered;
	int servmsg_timeout;
	int servmsg_handled;

	struct timer_loop tm_loop;

	long spdnet_alive_interval;
	pthread_t pid;

	void *user_data;
};

int servhub_init(struct servhub *hub,
                 const char *id,
                 const char *router_addr,
                 struct spdnet_nodepool *snodepool);
int servhub_close(struct servhub *hub);

int servhub_register_servarea(struct servhub *hub,
                              const char *area_name,
                              struct service *services,
                              const char *sockid,
                              struct spdnet_node **__snode);
int servhub_unregister_servarea(struct servhub *hub,
                                const char *area_name,
                                const char *sockid);

void servhub_mandate_snode(struct servhub *hub, struct spdnet_node *snode);
void servhub_recall_snode(struct servhub *hub, struct spdnet_node *snode);

service_handler_func_t
servhub_set_prepare(struct servhub *hub, service_handler_func_t prepare_cb);
service_handler_func_t
servhub_set_finished(struct servhub *hub, service_handler_func_t finished_cb);

typedef void (*servcall_cb)(struct servmsg *sm, void *arg, int flag);
void servhub_servcall(struct servhub *hub, struct servmsg *sm,
                      servcall_cb cb, void *arg, long timeout);
int servhub_servcall_local(struct servhub *hub, struct servmsg *sm, long timeout);

int servhub_loop(struct servhub *hub, long timeout);

/*
 * default servhub
 */

struct servhub *default_servhub(void);

#ifdef __cplusplus
}
#endif
#endif
