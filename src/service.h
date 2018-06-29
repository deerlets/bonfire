#ifndef __ZERO_SERVICE_H
#define __ZERO_SERVICE_H

#include <stddef.h>
#include <string.h>
#include <semaphore.h>
#include "spdnet.h"
#include "list.h"
#include "mutex.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * servmsg
 */

struct servmsg {
	struct spdnet_msg request;
	struct spdnet_msg response;
	struct spdnet_node *snode;

	void *reqserv;
	size_t reqserv_len;
	int rc;
};

void servmsg_init(struct servmsg *sm, struct spdnet_msg *msg,
                  struct spdnet_node *snode);
void servmsg_close(struct servmsg *sm);

static inline const char *servmsg_reqid(struct servmsg *sm)
{
	return spdnet_msg_gets(&sm->request, "name");
}

static inline void *servmsg_reqhdr_data(struct servmsg *sm)
{
	return zmq_msg_data(MSG_HEADER(&sm->request));
}

static inline size_t servmsg_reqhdr_size(struct servmsg *sm)
{
	return zmq_msg_size(MSG_HEADER(&sm->request));
}

static inline void *servmsg_reqcnt_data(struct servmsg *sm)
{
	return zmq_msg_data(MSG_CONTENT(&sm->request));
}

static inline size_t servmsg_reqcnt_size(struct servmsg *sm)
{
	return zmq_msg_size(MSG_CONTENT(&sm->request));
}

static inline int
servmsg_respcnt_reset_data(struct servmsg *sm, const void *data, int size)
{
	if (size == -1)
		size = strlen((const char *)data);

	zmq_msg_close(MSG_CONTENT(&sm->response));
	zmq_msg_init_size(MSG_CONTENT(&sm->response), size);
	memcpy(zmq_msg_data(MSG_CONTENT(&sm->response)), data, size);
	return 0;
}

/*
 * service
 */

typedef int (*service_handler_func_t)(struct servmsg *sm);

struct service {
	const char *name;
	service_handler_func_t handler;
	const char *desc;
	int visible;
	unsigned int tag;
	struct service *hash_next;
	struct service *hash_prev;
	struct list_head node;
};

#define SERVICE_INIT(name, handler, desc) \
	{ name, handler, desc, 1, 0, NULL, NULL }
#define SERVICE_INIT_PRIVATE(name, handler, desc) \
	{ name, handler, desc, 0, 0, NULL, NULL }

#define SERVICE_ERRNO_MAP(XX) \
	XX(EOK, "OK") \
	XX(EASYNCREPLY, "async reply") \
	XX(ENOSERV, "service unknown") \
	XX(ENOREQ, "request unknown") \
	XX(EINVAL, "invalid argument") \
	XX(ENORES, "resource not found") \
	XX(ERES, "resource error") \
	XX(ETIMEOUT, "request timeout") \
	XX(ESERVICECALL, "service call error") \
	XX(EIO, "io error")

typedef enum {
#define XX(code, _) SERVICE_##code,
	SERVICE_ERRNO_MAP(XX)
#undef XX
	SERVICE_ERRNO_MAX = 1000
} service_errno_t;

const char *service_strerror(int err);

/*
 * servarea
 */

struct servarea {
	const char *name;
	struct service **servtab;
	struct list_head services;
	struct list_head node;
	struct list_head sb_node;
};

int servarea_init(struct servarea *sa, const char *name);
int servarea_close(struct servarea *sa);
void servarea_register_service(struct servarea *sa, struct service *service);
void servarea_unregister_service(struct servarea *sa, struct service *service);
void servarea_register_service_batch(struct servarea *sa, struct service *services);
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

#define DEFAULT_SERVICE_CALL_TIMEOUT 1000

struct servhub {
	const char *name;
	const char *router_addr;

	struct spdnet_nodepool *serv_snodepool;
	struct spdnet_nodepool *req_snodepool;
	struct spdnet_node *spublish;
	struct spdnet_multicast *smulticast;

	struct list_head servareas;
	mutex_t servareas_lock;
};

int servhub_init(struct servhub *hub, const char *name, const char *router_addr,
                 struct spdnet_nodepool *serv_snodepool,
                 struct spdnet_nodepool *req_snodepool,
                 struct spdnet_node *spublish,
                 struct spdnet_multicast *smulticast);
int servhub_close(struct servhub *hub);
int servhub_register_service(struct servhub *hub, const char *name,
                             struct service *services,
                             struct spdnet_node **__snode);
int servhub_unregister_service(struct servhub *hub, const char *name);
int servhub_service_call(struct servhub *hub, struct spdnet_msg *msg);
int servhub_service_request(struct servhub *hub, struct spdnet_msg *msg);
int servhub_run(struct servhub *hub);

struct servhub *default_servhub(void);

#ifdef __cplusplus
}
#endif
#endif
