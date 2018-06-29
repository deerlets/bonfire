#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <gtest/gtest.h>
#include "spdnet.h"
#include "task.h"

#define INNER_ROUTER_ADDRESS "tcp://127.0.0.1:8338"
#define OUTER_ROUTER_ADDRESS "tcp://0.0.0.0:8339"

TEST(spdnet, basic)
{
	void *ctx = spdnet_ctx_create();
	struct spdnet_router router;
	struct task router_task;
	spdnet_router_init(&router, "router_inner", ctx);
	spdnet_router_bind(&router, INNER_ROUTER_ADDRESS);
	task_init(&router_task, "router_task",
	          (task_run_func_t)spdnet_router_run, &router);
	task_start(&router_task);

	int rc;
	struct spdnet_node service, requester;
	struct spdnet_msg msg;

	spdnet_node_init(&service, SPDNET_NODE, ctx);
	spdnet_setid(&service, "service", strlen("service"));
	rc = spdnet_connect(&service, INNER_ROUTER_ADDRESS);
	ASSERT_NE(rc, -1);
	rc = spdnet_register(&service);
	ASSERT_NE(rc, -1);

	spdnet_node_init(&requester, SPDNET_NODE, ctx);
	rc = spdnet_connect(&requester, INNER_ROUTER_ADDRESS);
	ASSERT_NE(rc, -1);
	SPDNET_MSG_INIT_DATA(&msg, "service", "hello", "I'm xiedd.");
	rc = spdnet_sendmsg(&requester, &msg);
	ASSERT_NE(rc, -1);
	spdnet_msg_close(&msg);

	spdnet_msg_init(&msg);
	rc = spdnet_recvmsg(&service, &msg, 0);
	ASSERT_NE(rc, -1);
	ASSERT_EQ(zmq_msg_size(MSG_SOCKID(&msg)), 5);
	ASSERT_EQ(zmq_msg_size(MSG_HEADER(&msg)), 5);
	ASSERT_EQ(zmq_msg_size(MSG_CONTENT(&msg)), 10);
	ASSERT_EQ(memcmp(zmq_msg_data(MSG_HEADER(&msg)), "hello", 5), 0);
	ASSERT_EQ(memcmp(zmq_msg_data(MSG_CONTENT(&msg)), "I'm xiedd.", 10), 0);
	zmq_msg_close(MSG_CONTENT(&msg));
	zmq_msg_init_size(MSG_CONTENT(&msg), 17);
	memcpy(zmq_msg_data(MSG_CONTENT(&msg)), "Welcome to zerox.", 17);
	rc = spdnet_sendmsg(&service, &msg);
	ASSERT_NE(rc, -1);
	spdnet_msg_close(&msg);

	sleep(1);
	spdnet_msg_init(&msg);
	rc = spdnet_recvmsg(&requester, &msg, 0);
	ASSERT_NE(rc, -1);
	ASSERT_EQ(zmq_msg_size(MSG_SOCKID(&msg)), 7);
	ASSERT_EQ(zmq_msg_size(MSG_HEADER(&msg)), 5);
	ASSERT_EQ(zmq_msg_size(MSG_CONTENT(&msg)), 17);
	ASSERT_EQ(memcmp(zmq_msg_data(MSG_HEADER(&msg)), "hello", 5), 0);
	ASSERT_EQ(memcmp(zmq_msg_data(MSG_CONTENT(&msg)), "Welcome to zerox.", 17), 0);
	spdnet_msg_close(&msg);

	ASSERT_EQ(spdnet_router_msg_routerd(&router), 3);
	ASSERT_EQ(spdnet_router_msg_dropped(&router), 0);

	zmq_send(spdnet_node_get_socket(&requester), "service", 7, 0);
	sleep(1);
	ASSERT_EQ(spdnet_router_msg_routerd(&router), 3);
	ASSERT_EQ(spdnet_router_msg_dropped(&router), 1);

	spdnet_node_close(&requester);
	spdnet_node_close(&service);

	task_stop(&router_task);
	task_close(&router_task);
	spdnet_router_close(&router);
	spdnet_ctx_destroy(ctx);
}

/*
 * spdnet nodepool
 */

static void recvmsg_cb(struct spdnet_node *snode, struct spdnet_msg *msg)
{
	spdnet_nodepool_put((struct spdnet_nodepool *)snode->user_data, snode);
}

TEST(spdnet, nodepoll)
{
	int rc;
	void *ctx = spdnet_ctx_create();
	struct spdnet_nodepool snodepool;
	spdnet_nodepool_init(&snodepool, 1, ctx);

	struct spdnet_msg msg;
	SPDNET_MSG_INIT_DATA(&msg, "gene", "info", NULL);
	struct spdnet_node *p = spdnet_nodepool_get(&snodepool);
	p->user_data = &snodepool;
	rc = spdnet_connect(p, "tcp://192.168.31.12:1234");
	assert(rc == 0);
	rc = spdnet_sendmsg(p, &msg);
	assert(rc == 0);
	spdnet_recvmsg_async(p, recvmsg_cb, 3000);
	assert(rc == 0);

	while (snodepool.nr_snode)
		spdnet_nodepool_run(&snodepool);

	spdnet_nodepool_close(&snodepool);
	spdnet_ctx_destroy(ctx);
}

/*
 * spdnet router
 */

TEST(spdnet, router)
{
	int rc;
	void *ctx = spdnet_ctx_create();
	struct spdnet_router inner, outer;

	// router inner
	rc = spdnet_router_init(&inner, "router-inner", ctx);
	assert(rc == 0);
	rc = spdnet_router_bind(&inner, INNER_ROUTER_ADDRESS);
	assert(rc == 0);
	struct task inner_task;
	task_init(&inner_task, "router-inner-task",
	          (task_run_func_t)spdnet_router_run, &inner);
	task_start(&inner_task);
	sleep(1);

	// router outer
	char inner_id[SPDNET_SOCKID_SIZE];
	size_t inner_len;
	rc = spdnet_router_init(&outer, NULL, ctx);
	assert(rc == 0);
	rc = spdnet_router_bind(&outer, OUTER_ROUTER_ADDRESS);
	assert(rc == 0);
	rc = spdnet_router_associate(&outer, INNER_ROUTER_ADDRESS,
	                             inner_id, &inner_len);
	assert(rc == 0);
	spdnet_router_set_gateway(&outer, inner_id, inner_len, SPDNET_ROUTER);
	struct task outer_task;
	task_init(&outer_task, "router-outer-task",
	          (task_run_func_t)spdnet_router_run, &outer);
	task_start(&outer_task);
	sleep(1);

	struct spdnet_msg msg;
	struct spdnet_node requester, service;
	spdnet_msg_init(&msg);
	spdnet_node_init(&requester, SPDNET_NODE, ctx);
	spdnet_setid(&requester, "requester", strlen("requester"));
	spdnet_node_init(&service, SPDNET_NODE, ctx);
	spdnet_setid(&service, "service", strlen("service"));

	rc = spdnet_connect(&requester, OUTER_ROUTER_ADDRESS);
	assert(rc == 0);
	rc = spdnet_connect(&service, INNER_ROUTER_ADDRESS);
	assert(rc == 0);
	rc = spdnet_register(&service);
	assert(rc == 0);

	// send from requester to service
	spdnet_msg_close(&msg);
	SPDNET_MSG_INIT_DATA(&msg, "service", "hello", "world");
	rc = spdnet_sendmsg(&requester, &msg);
	assert(rc == 0);
	sleep(1);
	rc = spdnet_recvmsg(&service, &msg, 0);
	assert(rc == 0);
	assert(zmq_msg_size(MSG_SOCKID(&msg)) == 9);
	assert(zmq_msg_size(MSG_HEADER(&msg)) == 5);
	assert(memcmp("requester", zmq_msg_data(MSG_SOCKID(&msg)), 9) == 0);
	assert(memcmp("hello", zmq_msg_data(MSG_HEADER(&msg)), 5) == 0);
	sleep(1);

	// reply from service to requester
	zmq_msg_close(MSG_HEADER(&msg));
	zmq_msg_init_size(MSG_HEADER(&msg), 5+6);
	memcpy(zmq_msg_data(MSG_HEADER(&msg)), "hello_reply", 5+6);
	rc = spdnet_sendmsg(&service, &msg);
	assert(rc == 0);
	sleep(1);
	rc = spdnet_recvmsg(&requester, &msg, 0);
	assert(rc == 0);
	assert(zmq_msg_size(MSG_SOCKID(&msg)) == 7);
	assert(zmq_msg_size(MSG_HEADER(&msg)) == 5+6);
	assert(memcmp("service", zmq_msg_data(MSG_SOCKID(&msg)), 7) == 0);
	assert(memcmp("hello_reply", zmq_msg_data(MSG_HEADER(&msg)), 5+6) == 0);
	sleep(1);

	task_stop(&inner_task);
	task_stop(&outer_task);
	spdnet_msg_close(&msg);
	spdnet_node_close(&requester);
	spdnet_node_close(&service);
	spdnet_router_close(&outer);
	spdnet_router_close(&inner);
	spdnet_ctx_destroy(ctx);
}

/*
 * spdnet pgm
 */

static void *sub_routine(void *sub)
{
	zmq_msg_t msg;
	zmq_msg_init(&msg);
	zmq_msg_recv(&msg, sub, 0);
	assert(strcmp((char *)zmq_msg_data(&msg), "hello pgm") == 0);
	zmq_msg_close(&msg);
	return NULL;
}

TEST(spdnet, pgm)
{
	// always fails
	return;
	void *ctx = spdnet_ctx_create();
	void *pub = zmq_socket(ctx, ZMQ_PUB);
	void *sub = zmq_socket(ctx, ZMQ_SUB);

	//const char *url = "tcp://127.0.0.1:1234";
	const char *url = "epgm://enp0s25;239.255.12.24:5964";
	int rc = zmq_bind(pub, url);
	assert(rc == 0);
	rc = zmq_connect(sub, url);
	rc = zmq_setsockopt(sub, ZMQ_SUBSCRIBE, "", 0);
	assert(rc == 0);
	pthread_t tid;
	pthread_create(&tid, NULL, sub_routine, sub);
	sleep(3);
	zmq_msg_t msg;
	zmq_msg_init_size(&msg, 10);
	memcpy(zmq_msg_data(&msg), "hello pgm\0", 10);
	zmq_msg_send(&msg, pub, 0);
	zmq_msg_close(&msg);
	pthread_join(tid, NULL);

	zmq_close(pub);
	zmq_close(sub);
	spdnet_ctx_destroy(ctx);
}
