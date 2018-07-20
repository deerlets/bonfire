#include "zsocket.h"
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <unistd.h>
#ifdef __WIN32
#include <Winsock2.h>
typedef int socklen_t;
#define SHUT_RD SD_RECEIVE
#define SHUT_WR SD_SEND
#define SHUT_RDWR SD_BOTH
#else
#include <netinet/in.h>
#include <sys/socket.h>
#endif

static int lib_init;

static LIST_HEAD(socks);
static int nfds_read;
static fd_set __fds_read;
static int nfds_write;
static fd_set __fds_write;

static struct zsocket_status __status;

void zsocket_init(struct zsocket *s)
{
	if (!lib_init) {
#ifdef __WIN32
		WSADATA wsaData;
		if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0)
			exit(EXIT_FAILURE);
#endif

		nfds_read = 0;
		FD_ZERO(&__fds_read);
		nfds_write = 0;
		FD_ZERO(&__fds_write);

		lib_init = 1;
	}

	s->fd = -1;
	memset(&s->laddr, 0, sizeof(s->laddr));
	memset(&s->raddr, 0, sizeof(s->raddr));
	s->type = ZS_T_NONE;
	s->state = 0;
	s->tick = 0;
	s->stall = STALL_INTERVAL;

	s->rbuf = NULL;
	s->wbuf = NULL;
	s->sdata = NULL;
	s->user_data = NULL;

	s->s_ops.close_cb = NULL;
	s->s_ops.read_cb = NULL;
	s->s_ops.connected_cb = NULL;
	s->s_ops.connection_cb = NULL;

	INIT_LIST_HEAD(&s->node);
}

static void __zsocket_close(struct zsocket *s)
{
	assert(s->state & ZS_S_EOF);
	assert(s->type != ZS_T_NONE);

	list_del(&s->node);

	if (s->type == ZS_T_SERVER) {
		struct zsocket *pos;
		list_for_each_entry(pos, &socks, node) {
			if (pos->laddr.sin_port == s->laddr.sin_port)
				zsocket_close(pos, NULL);
		}
	}

	shutdown(s->fd, SHUT_RDWR);
	close(s->fd);
	s->fd = -1;

	if (s->rbuf) qbuf_delete(s->rbuf);
	s->rbuf = NULL;
	if (s->wbuf) qbuf_delete(s->wbuf);
	s->wbuf = NULL;
	if (s->sdata) zsocket_sdata_free(s);
	s->sdata = NULL;
	s->user_data = NULL;

	s->s_ops.close_cb = NULL;
	s->s_ops.read_cb = NULL;
	s->s_ops.connected_cb = NULL;
	s->s_ops.connection_cb = NULL;
}

void zsocket_close(struct zsocket *s, zsocket_close_cb cb)
{
	assert((s->state & ZS_S_EOF) == 0);

	if (nfds_read == s->fd + 1)
		nfds_read--;
	FD_CLR(s->fd, &__fds_read);

	if (nfds_write == s->fd + 1)
		nfds_write--;
	FD_CLR(s->fd, &__fds_write);

	s->state |= ZS_S_EOF;
	/*if (cb)*/ s->s_ops.close_cb = cb;

	__status.nr_closed++;
	__status.nr_current--;
	if (s->type == ZS_T_CLIENT)
		__status.nr_current_client--;
	else if (s->type == ZS_T_SERVER)
		__status.nr_current_server--;
	else if (s->type == ZS_T_CONNECTION)
		__status.nr_current_connection--;
}

int zsocket_connect(struct zsocket *client,
                    const struct sockaddr* addr,
                    zsocket_connected_cb cb)
{
	assert((client->state & ZS_S_EOF) == 0);

	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1) return -1;

	if (connect(fd, addr, sizeof(*addr)) == -1) {
		close(fd);
		return -1;
	}

	int opt = 1;
#ifdef __WIN32
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt));
#else
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif

	struct sockaddr_in laddr;
	socklen_t lsocklen = sizeof(laddr);
	getsockname(fd, (struct sockaddr*)&laddr, &lsocklen);

	client->fd = fd;
	client->raddr = *(struct sockaddr_in *)addr;
	client->laddr = laddr;
	client->type = ZS_T_CLIENT;
	client->tick = time(NULL);
	client->s_ops.connected_cb = cb;
	list_add(&client->node, &socks);
	__status.nr_total++;
	__status.nr_current++;
	__status.nr_current_client++;

	if (cb) cb(client);
	return 0;
}

int zsocket_listen(struct zsocket *server,
                   const struct sockaddr* addr,
                   zsocket_connection_cb cb)
{
	assert((server->state & ZS_S_EOF) == 0);
	assert(cb);

	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1) return -1;

	if (bind(fd, addr, sizeof(*addr)) == -1) {
		close(fd);
		return -1;
	}
	listen(fd, 100);

	int opt = 1;
#ifdef __WIN32
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt));
#else
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif

	server->fd = fd;
	server->laddr = *(struct sockaddr_in *)addr;
	server->type = ZS_T_SERVER;
	server->s_ops.connection_cb = cb;
	list_add(&server->node, &socks);
	__status.nr_total++;
	__status.nr_current++;
	__status.nr_current_server++;

	// auto start reading
	if (nfds_read < server->fd + 1)
		nfds_read = server->fd + 1;
	FD_SET(server->fd, &__fds_read);
	server->state |= ZS_S_READ_ENABLE;
	return 0;
}

struct zsocket *zsocket_accept(struct zsocket *server)
{
	assert((server->state & ZS_S_EOF) == 0);

	struct zsocket *conn = calloc(1, sizeof(struct zsocket));
	if (conn == NULL) return NULL;
	zsocket_init(conn);

	struct sockaddr_in raddr;
	socklen_t rsocklen = sizeof(raddr);
	int fd = accept(server->fd, (struct sockaddr*)&raddr, &rsocklen);
	if (fd == -1) {
		__zsocket_close(conn);
		free(conn);
		return NULL;
	}

	int opt = 1;
#ifdef __WIN32
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt));
#else
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif

	struct sockaddr_in laddr;
	socklen_t lsocklen = sizeof(laddr);
	getsockname(fd, (struct sockaddr*)&laddr, &lsocklen);

	conn->fd = fd;
	conn->raddr = raddr;
	conn->laddr = laddr;
	conn->type = ZS_T_CONNECTION;
	conn->tick = time(NULL);
	list_add(&conn->node, &socks);
	__status.nr_total++;
	__status.nr_current++;
	__status.nr_current_connection++;

	return conn;
}

int zsocket_iseof(struct zsocket *s)
{
	return s->state & ZS_S_EOF;
}

void *zsocket_sdata(struct zsocket *s)
{
	return s->sdata;
}

void *zsocket_sdata_alloc(struct zsocket *s, size_t size)
{
	if (s->sdata)
		return NULL;

	s->sdata = calloc(1, size);
	return s->sdata;
}

void zsocket_sdata_free(struct zsocket *s)
{
	free(s->sdata);
	s->sdata = NULL;
}

void zsocket_read_start(struct zsocket *s, zsocket_read_cb cb)
{
	assert((s->state & ZS_S_EOF) == 0);
	assert((s->state & ZS_S_READ_ENABLE) == 0);
	assert(cb);

	if (nfds_read < s->fd + 1)
		nfds_read = s->fd + 1;
	FD_SET(s->fd, &__fds_read);
	s->state |= ZS_S_READ_ENABLE;
	s->s_ops.read_cb = cb;
}

void zsocket_read_stop(struct zsocket *s)
{
	assert((s->state & ZS_S_EOF) == 0);
	assert(s->state & ZS_S_READ_ENABLE);

	if (nfds_read == s->fd + 1)
		nfds_read--;
	FD_CLR(s->fd, &__fds_read);
	s->state &= ~ZS_S_READ_ENABLE;
	s->s_ops.read_cb = NULL;
}

size_t zsocket_write(struct zsocket *s, const void *buf, size_t len)
{
	assert((s->state & ZS_S_EOF) == 0);

	// lazy allocate wbuf
	if ((s->state & ZS_S_WRITE_ENABLE) == 0) {
		assert(!s->wbuf);
		s->wbuf = qbuf_new(WRITE_BUF_SIZE);
		if (!s->wbuf) return -1;

		if (nfds_write < s->fd + 1)
			nfds_write = s->fd + 1;
		FD_SET(s->fd, &__fds_write);
		s->state |= ZS_S_WRITE_ENABLE;
	}

	// we can write safely now
	return qbuf_write(s->wbuf, buf, len);
}

static void zsocket_handle_recv(struct zsocket *s)
{
	assert(s->type != ZS_T_NONE);
	assert((s->state & ZS_S_EOF) == 0);
	assert(s->state & ZS_S_READ_ENABLE);

	if (s->type == ZS_T_SERVER) {
		assert(s->s_ops.connection_cb);
		s->s_ops.connection_cb(s);
		return;
	}

	// lazy allocate rbuf
	if (!s->rbuf) {
		s->rbuf = qbuf_new(READ_BUF_SIZE);
		if (!s->rbuf) return;
	}

	// we can recv safely now
	int nrecv = recv(s->fd, qbuf_rawbuf_in_pos(s->rbuf),
	                 qbuf_spare(s->rbuf), 0);
	if (nrecv == -1)
		s->state &= ZS_S_READ_FAILED;
	else if (nrecv > 0)
		qbuf_offset_in_head(s->rbuf, nrecv);
	s->tick = time(NULL);

	assert(s->s_ops.read_cb);

	void *buf = qbuf_rawbuf_out_pos(s->rbuf);
	size_t len = qbuf_used(s->rbuf);
	int nr = s->s_ops.read_cb(s, buf, len);
	assert(nr >= 0);
	if (nr > len) nr = len;

	if (nr) {
		qbuf_offset_out_head(s->rbuf, nr);
		qbuf_collect(s->rbuf, QBUF_COLLECT_POLICY_LESS_SPARE);
	}

	if (!qbuf_spare(s->rbuf) &&
	    qbuf_realloc(s->rbuf, qbuf_size(s->rbuf) << 1)) {
		s->state &= ZS_S_RBUF_RUNOUT;
		zsocket_close(s, NULL);
	}
}

static void zsocket_handle_send(struct zsocket *s)
{
	assert(s->type != ZS_T_NONE);
	assert((s->state & ZS_S_EOF) == 0);
	assert(s->state & ZS_S_WRITE_ENABLE);
	assert(s->wbuf);

	if (!qbuf_used(s->wbuf))
		return;

	int nsend = send(s->fd, qbuf_rawbuf_out_pos(s->wbuf),
	                 qbuf_used(s->wbuf), 0);
	if (nsend == -1) {
		s->state &= ZS_S_WRITE_FAILED;
		zsocket_close(s, NULL);
	} else if (nsend > 0) {
		qbuf_offset_out_head(s->wbuf, nsend);
		qbuf_collect(s->wbuf, QBUF_COLLECT_POLICY_LESS_SPARE);

		if (!qbuf_spare(s->wbuf)) {
			s->state &= ZS_S_WBUF_RUNOUT;
			zsocket_close(s, NULL);
		}
	}
}

static int zsocket_poll(int timeout)
{
	struct timeval tv = {
		.tv_sec = timeout / 1000,
		.tv_usec = timeout % 1000 * 1000,
	};

	fd_set fds_read;
	memcpy(&fds_read, &__fds_read, sizeof(fd_set));
	fd_set fds_write;
	memcpy(&fds_write, &__fds_write, sizeof(fd_set));
	int nfds = nfds_read > nfds_write ? nfds_read : nfds_write;

	int nfds_selected = select(nfds, &fds_read, &fds_write, NULL, &tv);

	if (nfds_selected == 0)
		return 0;
	else if (nfds_selected == -1) {
		// EINTR for CTRL-C while debugging in gdb
		if (errno == EINTR)
			return 0;
		return -1;
	}

	int handled;
	struct zsocket *pos;
	list_for_each_entry(pos, &socks, node) {
		handled = 0;

		if (FD_ISSET(pos->fd, &fds_read)) {
			zsocket_handle_recv(pos);
			handled = 1;
		}

		if (FD_ISSET(pos->fd, &fds_write)) {
			zsocket_handle_send(pos);
			handled = 1;
		}

		if (handled && --nfds_selected == 0)
			break;
	}

	return 0;
}

static void zsocket_do_close()
{
	struct zsocket *pos, *n;
	list_for_each_entry_safe(pos, n, &socks, node) {
		if (pos->type == ZS_T_CONNECTION &&
		    time(NULL) - pos->tick > pos->stall) {
			pos->state &= ZS_S_TIMEOUT;
			zsocket_close(pos, NULL);
		}

		if (pos->state & ZS_S_EOF) {
			if (pos->s_ops.close_cb)
				pos->s_ops.close_cb(pos);
			__zsocket_close(pos);
			if (pos->type == ZS_T_CONNECTION)
				free(pos);
		}
	}
}

int zsocket_loop(int timeout)
{
	int rc;

	if (timeout < 100)
		timeout = 100;

	if ((rc = zsocket_poll(timeout)) == -1)
		return rc;

	zsocket_do_close();

	return rc;
}

struct zsocket_status *zsocket_status()
{
	return &__status;
}
