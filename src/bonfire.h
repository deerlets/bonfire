#ifndef __BONFIRE_BONFIRE_H
#define __BONFIRE_BONFIRE_H

#include <stddef.h> //size_t

#ifdef __cplusplus
extern "C" {
#endif

#define BONFIRE_ERRNO_MAP(XX) \
	XX(EOK, "OK") \
	XX(EINVAL, "Invalid argument") \
	XX(EEXIST, "Target exists") \
	XX(ENOTFOUND, "Target not found") \
	XX(ETIMEOUT, "Operation timeout") \
	XX(ECANCEL, "Operation canceled") \
	XX(EPERM, "Permission deny")

typedef enum {
#define XX(code, _) BONFIRE_##code,
	BONFIRE_ERRNO_MAP(XX)
#undef XX
	BONFIRE_ERRNO_MAX = 1000
} bonfire_errno_t;

struct bmsg;
struct bonfire;

/*
 * bmsg
 */

void bmsg_pending(struct bmsg *bm);
void bmsg_filtered(struct bmsg *bm);
void bmsg_handled(struct bmsg *bm);

struct bonfire *bmsg_get_bonfire(struct bmsg *bm);
void *bmsg_get_user_data(struct bmsg *bm);
void bmsg_set_user_data(struct bmsg *bm, void *data);
void bmsg_get_request_header(struct bmsg *bm, void **header, size_t *size);
void bmsg_get_request_content(struct bmsg *bm, void **content, size_t *size);
void bmsg_write_response(struct bmsg *bm, const char *data);
void bmsg_write_response_size(struct bmsg *bm, const void *data, size_t size);

/*
 * bonfire cli
 */

#define BONFIRE_DEFAULT_TIMEOUT 5000

typedef void (*bonfire_service_cb)(struct bmsg *bm);
typedef void (*bonfire_servcall_cb)(struct bonfire *bf,
                                    const void *resp,
                                    size_t len,
                                    void *arg,
                                    int flag);
typedef void (*bonfire_subscribe_cb)(struct bonfire *bf,
                                     const void *resp,
                                     size_t len,
                                     void *arg,
                                     int flag);

struct bonfire *bonfire_new();
void bonfire_destroy(struct bonfire *bf);
int bonfire_connect(struct bonfire *bf, const char *remote_addr);
void bonfire_disconnect(struct bonfire *bf);
int bonfire_loop(struct bonfire *bf, long timeout);

void bonfire_get_id(struct bonfire *bf, void *id, size_t *len);
void bonfire_set_id(struct bonfire *bf, const void *id, size_t len);
void *bonfire_get_user_data(struct bonfire *bf);
void bonfire_set_user_data(struct bonfire *bf, void *data);

int bonfire_add_service(struct bonfire *bf, const char *header,
                         bonfire_service_cb cb);
int bonfire_del_service(struct bonfire *bf, const char *header);

void bonfire_set_servcall_timeout(struct bonfire *bf, long timeout);

int bonfire_servcall(struct bonfire *bf,
                     const char *header,
                     const char *content,
                     char **result); // if not null, user should free it

void bonfire_servcall_async(struct bonfire *bf,
                            const char *header,
                            const char *content,
                            bonfire_servcall_cb cb,
                            void *arg);

int bonfire_publish(struct bonfire *bf, const char *topic, const char *content);

int bonfire_subscribe(struct bonfire *bf,
                      const char *topic,
                      bonfire_subscribe_cb cb,
                      void *arg);

int bonfire_unsubscribe(struct bonfire *bf, const char *topic);

/*
 * bonfire broker
 */

struct bonfire_broker;

struct bonfire_broker *bonfire_broker_new(const char *listen_addr,
                                          const char *pub_addr,
                                          const char *sub_addr);
void bonfire_broker_destroy(struct bonfire_broker *bbrk);
int bonfire_broker_loop(struct bonfire_broker *bbrk, long timeout);
void bonfire_broker_set_gateway(struct bonfire_broker *bbrk,
                                const char *gateway_addr);
void bonfire_broker_set_cache_file(struct bonfire_broker *bbrk,
                                   const char *cache_file);

#ifdef __cplusplus
}
#endif
#endif
