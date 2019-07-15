#ifndef __ZEBRA_SERVICE_H
#define __ZEBRA_SERVICE_H

#include <assert.h>
#include <stddef.h>
#include <string.h>
#include <pthread.h>
#include <spdnet.h>
#include "list.h"

#define SERVAREA_DELIMITER "://"
#define SERVICE_DELIMITER '/'

#ifdef __cplusplus
extern "C" {
#endif

/*
 * service_errno
 */

#define SERVICE_ERRNO_MAP(XX) \
	XX(EOK, "OK") \
	XX(ETIMEOUT, "timeout") \
	XX(ENOSERV, "service unknown") \
	XX(ENOREQ, "request unknown")

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

enum servmsg_state {
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
	struct spdnet_msg request;
	struct spdnet_msg response;
	struct spdnet_node *snode;

	const void *src;
	size_t src_len;
	const void *dest;
	size_t dest_len;

	const void *header;
	size_t header_len;
	// uri scheme, area always equal header
	size_t area_len;
	const void *service;
	size_t service_len;

	void *user_data;
	int rc;
	const char *errmsg;
	int state;

	struct zebra_list_head node;
};

void servmsg_init(struct servmsg *sm, struct spdnet_msg *msg,
                  struct spdnet_node *snode);
void servmsg_init_uninterruptible(struct servmsg *sm, struct spdnet_msg *msg,
                                  struct spdnet_node *snode);
void servmsg_close(struct servmsg *sm);

int servmsg_interruptible(struct servmsg *sm);
void servmsg_pending(struct servmsg *sm);
void servmsg_filtered(struct servmsg *sm);
void servmsg_timeout(struct servmsg *sm);
void servmsg_handled(struct servmsg *sm, int rc);
int servmsg_error(struct servmsg *sm, int err, const char *errmsg);

const char *servmsg_reqid(struct servmsg *sm);
int servmsg_respcnt_reset_data(struct servmsg *sm, const void *data, int size);

/*
 * service
 */

typedef void (*service_prepare_func_t)(struct servmsg *sm);
typedef int (*service_handler_func_t)(struct servmsg *sm);

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

struct servarea {
	const char *name;
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
	const char *id;
	const char *router_addr;
	struct spdnet_nodepool *snodepool;
	// default snode used by servhub
	struct spdnet_node *snode;

	service_prepare_func_t prepare_cb;
	service_prepare_func_t finished_cb;

	struct zebra_list_head servareas;
	pthread_mutex_t servareas_lock;

	struct zebra_list_head servmsgs;
	int servmsg_total;
	int servmsg_doing;
	int servmsg_filtered;
	int servmsg_timeout;
	int servmsg_handled;

	void *user_data;
};

int servhub_init(struct servhub *hub, const char *id, const char *router_addr,
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
service_prepare_func_t
servhub_set_prepare(struct servhub *hub, service_prepare_func_t prepare_cb);
service_prepare_func_t
servhub_set_finished(struct servhub *hub, service_prepare_func_t finished_cb);
int servhub_service_call(struct servhub *hub, struct spdnet_msg *msg);
int servhub_service_request(struct servhub *hub, struct spdnet_msg *msg,
                            long timeout);
int servhub_loop(struct servhub *hub, long timeout);

struct servhub *default_servhub(void);

#ifdef __cplusplus
}
#endif
#endif
