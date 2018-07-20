#ifndef __ZERO_ZST_H
#define __ZERO_ZST_H

#include "qbuf.h"
#include "list.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __WIN32
#include <Winsock2.h>
#else
#include <arpa/inet.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define CONV_B(ptr) (*(uint8_t*)(ptr))
#define CONV_W(ptr) (*(uint16_t*)(ptr))
#define CONV_L(ptr) (*(uint32_t*)(ptr))
#define CONV_Q(ptr) (*(uint64_t*)(ptr))

#define READ_BUF_SIZE 8192
#define WRITE_BUF_SIZE 8192
#define STALL_INTERVAL 60 * 5

#define ZS_S_EOF          0x1
#define ZS_S_TIMEOUT      (1 << 1)
#define ZS_S_READ_ENABLE  (1 << 2)
#define ZS_S_WRITE_ENABLE (1 << 3)
#define ZS_S_READ_FAILED  (1 << 4)
#define ZS_S_WRITE_FAILED (1 << 5)
#define ZS_S_RBUF_RUNOUT  (1 << 6)
#define ZS_S_WBUF_RUNOUT  (1 << 7)

enum __zsocket_type {
	ZS_T_NONE = 0,
	ZS_T_CLIENT,
	ZS_T_SERVER,
	ZS_T_CONNECTION,
};

struct zsocket;

typedef void (*zsocket_close_cb)(struct zsocket *s);
typedef int (*zsocket_read_cb)(struct zsocket *s, const void *buf, int len);
typedef void (*zsocket_connected_cb)(struct zsocket *client);
typedef void (*zsocket_connection_cb)(struct zsocket *server);

struct socket_operations {
	zsocket_close_cb close_cb;
	zsocket_read_cb read_cb;
	zsocket_connected_cb connected_cb;
	zsocket_connection_cb connection_cb;
};

struct zsocket {
	int fd;
	// for listen
	struct sockaddr_in laddr;
	// for accpet & connect
	struct sockaddr_in raddr;
	int type;
	int state;
	// time of last recv(for detecting timeouts), 0 when timeout is disabled
	time_t tick;
	time_t stall;

	qbuf_t *rbuf;
	qbuf_t *wbuf;
	// stores application-specific data related to the zsocket
	void *sdata;
	void *user_data;
	struct socket_operations s_ops;

	struct list_head node;
};

void zsocket_init(struct zsocket *s);
void zsocket_close(struct zsocket *s, zsocket_close_cb cb);
int zsocket_connect(struct zsocket *client,
                    const struct sockaddr* addr,
                    zsocket_connected_cb cb);
int zsocket_listen(struct zsocket *server,
                   const struct sockaddr* addr,
                   zsocket_connection_cb cb);
struct zsocket *zsocket_accept(struct zsocket *server);

int zsocket_iseof(struct zsocket *s);
void *zsocket_sdata(struct zsocket *s);
void *zsocket_sdata_alloc(struct zsocket *s, size_t size);
void zsocket_sdata_free(struct zsocket *s);

void zsocket_read_start(struct zsocket *s, zsocket_read_cb cb);
void zsocket_read_stop(struct zsocket *s);
size_t zsocket_write(struct zsocket *s, const void *buf, size_t len);

int zsocket_loop(int timeout);

struct zsocket_status {
	int nr_current;
	int nr_total;
	int nr_closed;

	int nr_current_client;
	int nr_current_server;
	int nr_current_connection;
};

struct zsocket_status *zsocket_status();

#ifdef __cplusplus
}
#endif
#endif
