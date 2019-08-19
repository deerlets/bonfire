#ifndef __BONFIRE_BONFIRE_H
#define __BONFIRE_BONFIRE_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * bmsg
 */

struct bmsg;

void bmsg_pending(struct bmsg *bm);
void bmsg_filtered(struct bmsg *bm);
void bmsg_handled(struct bmsg *bm);

void *bmsg_get_user_arg(struct bmsg *bm);
void bmsg_set_user_arg(struct bmsg *bm, void *arg);
void bmsg_get_request_header(struct bmsg *bm, void **header, size_t *size);
void bmsg_get_request_content(struct bmsg *bm, void **content, size_t *size);
void bmsg_write_response(struct bmsg *bm, const char *data);
void bmsg_write_response_size(struct bmsg *bm, const void *data, size_t size);

/*
 * bonfire service
 */

typedef void (*service_handler_func_t)(struct bmsg *bm);

struct bonfire_service_info {
	const char *header;
	service_handler_func_t handler;
};

#define INIT_SERVICE(header, handler) { header, handler }

/*
 * bonfire cli
 */

struct bonfire;

struct bonfire *bonfire_new(const char *remote_addr,
                            const char *remote_id,
                            const char *local_id);
void bonfire_destroy(struct bonfire *bf);
int bonfire_loop(struct bonfire *bf, long timeout);

void bonfire_set_msg_arg(struct bonfire *bf, void *arg);

void bonfire_set_msg_prepare(struct bonfire *bf,
                             service_handler_func_t prepare_cb);

void bonfire_set_msg_finished(struct bonfire *bf,
                              service_handler_func_t finished_cb);

void bonfire_set_local_services(struct bonfire *bf,
                                struct bonfire_service_info *services);

int bonfire_servcall(struct bonfire *bf,
                     const char *header,
                     const char *content,
                     char **result, // if not null, user should free it
                     long timeout);

#define BONFIRE_SERVCALL_OK 0
#define BONFIRE_SERVCALL_NOSERV 1
#define BONFIRE_SERVCALL_TIMEOUT 2

typedef
void (*bonfire_servcall_cb)(const void *resp, size_t len, void *arg, int flag);

void bonfire_servcall_async(struct bonfire *bf,
                            const char *header,
                            const char *content,
                            bonfire_servcall_cb cb,
                            void *arg,
                            long timeout);

int bonfire_servsync(struct bonfire *bf);

/*
 * bonfire server
 */

struct bonfire_server;

struct bonfire_server *
bonfire_server_new(const char *listen_addr, const char *local_id);
void bonfire_server_destroy(struct bonfire_server *server);
int bonfire_server_loop(struct bonfire_server *server, long timeout);
void bonfire_server_set_gateway(struct bonfire_server *server,
                                const char *gateway_addr);

#ifdef __cplusplus
}
#endif
#endif
