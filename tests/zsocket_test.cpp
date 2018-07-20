#include <assert.h>
#include <gtest/gtest.h>
#include "zsocket.h"

#define LISTEN_PORT 5964

static int exit_flag;

static void close_cb(struct zsocket *s)
{
	struct zsocket_status *status = zsocket_status();
	ASSERT_EQ(status->nr_total, 3);
	ASSERT_EQ(status->nr_closed, 1);
	ASSERT_EQ(status->nr_current, 2);
	ASSERT_EQ(status->nr_current_client, 1);
	ASSERT_EQ(status->nr_current_server, 1);
	ASSERT_EQ(status->nr_current_connection, 0);
}

static int read_cb(struct zsocket *s, const void *buf, int len)
{
	if (len == 0 || len == -1) {
		zsocket_close(s, close_cb);
		return 0;
	}

	assert(5 == len);
	assert(strcmp("hello", (char *)buf) == 0);

	zsocket_close(s, close_cb);
	exit_flag = 1;
	return len;
}

void connection_cb(struct zsocket *server)
{
	struct zsocket *conn = zsocket_accept(server);
	assert(conn);

	struct zsocket_status *status = zsocket_status();
	ASSERT_EQ(status->nr_total, 3);
	ASSERT_EQ(status->nr_closed, 0);
	ASSERT_EQ(status->nr_current, 3);
	ASSERT_EQ(status->nr_current_client, 1);
	ASSERT_EQ(status->nr_current_server, 1);
	ASSERT_EQ(status->nr_current_connection, 1);

	zsocket_read_start(conn, read_cb);
}

TEST(zsocket, basic)
{
	int rc;
	struct zsocket_status *status;

	struct zsocket server;
	zsocket_init(&server);

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(LISTEN_PORT);
	addr.sin_addr.s_addr = inet_addr("0.0.0.0");
	rc = zsocket_listen(&server, (struct sockaddr *)&addr, connection_cb);
	ASSERT_EQ(rc, 0);
	status = zsocket_status();
	ASSERT_EQ(status->nr_total, 1);
	ASSERT_EQ(status->nr_closed, 0);
	ASSERT_EQ(status->nr_current, 1);
	ASSERT_EQ(status->nr_current_client, 0);
	ASSERT_EQ(status->nr_current_server, 1);
	ASSERT_EQ(status->nr_current_connection, 0);

	struct zsocket client;
	zsocket_init(&client);

	addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	ASSERT_EQ(zsocket_connect(&client, (struct sockaddr *)&addr, NULL), 0);
	status = zsocket_status();
	ASSERT_EQ(status->nr_total, 2);
	ASSERT_EQ(status->nr_closed, 0);
	ASSERT_EQ(status->nr_current, 2);
	ASSERT_EQ(status->nr_current_client, 1);
	ASSERT_EQ(status->nr_current_server, 1);
	ASSERT_EQ(status->nr_current_connection, 0);
	zsocket_write(&client, "hello", 5);

	while (!exit_flag) zsocket_loop(10000);

	zsocket_close(&client, NULL);
	ASSERT_EQ(status->nr_total, 3);
	ASSERT_EQ(status->nr_closed, 2);
	ASSERT_EQ(status->nr_current, 1);
	ASSERT_EQ(status->nr_current_client, 0);
	ASSERT_EQ(status->nr_current_server, 1);
	ASSERT_EQ(status->nr_current_connection, 0);

	zsocket_close(&server, NULL);
	ASSERT_EQ(status->nr_total, 3);
	ASSERT_EQ(status->nr_closed, 3);
	ASSERT_EQ(status->nr_current, 0);
	ASSERT_EQ(status->nr_current_client, 0);
	ASSERT_EQ(status->nr_current_server, 0);
	ASSERT_EQ(status->nr_current_connection, 0);

	zsocket_loop(0);
}
