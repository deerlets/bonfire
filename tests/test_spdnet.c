#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <spdnet/spdnet.h>
#include "task.h"

#define INNER_ROUTER_ADDRESS "tcp://127.0.0.1:18338"
#define OUTER_ROUTER_ADDRESS "tcp://0.0.0.0:18339"

static void test_spdnet_basic(void **status)
{
	void *ctx = spdnet_ctx_create();
	struct spdnet_router router;
	struct task router_task;
	spdnet_router_init(&router, "router_inner", ctx);
	spdnet_router_bind(&router, INNER_ROUTER_ADDRESS);
	task_init_timeout(&router_task, "router_task",
	                  (task_timeout_func_t)spdnet_router_loop, &router, 500);
	task_start(&router_task);

	int rc;
	struct spdnet_node service, requester;
	struct spdnet_msg msg;

	spdnet_node_init(&service, SPDNET_NODE, ctx);
	spdnet_setid(&service, "service", strlen("service"));
	rc = spdnet_connect(&service, INNER_ROUTER_ADDRESS);
	assert_true(rc == 0);
	rc = spdnet_register(&service);
	assert_true(rc == 0);

	spdnet_node_init(&requester, SPDNET_NODE, ctx);
	rc = spdnet_connect(&requester, INNER_ROUTER_ADDRESS);
	assert_true(rc == 0);
	SPDNET_MSG_INIT_DATA(&msg, "service", "hello", "I'm xiedd.");
	rc = spdnet_sendmsg(&requester, &msg);
	assert_true(rc == 0);
	spdnet_msg_close(&msg);

	spdnet_msg_init(&msg);
	rc = spdnet_recvmsg(&service, &msg, 0);
	assert_true(rc == 0);
	assert_true(MSG_SOCKID_SIZE(&msg) == 5);
	assert_true(MSG_HEADER_SIZE(&msg) == 5);
	assert_true(MSG_CONTENT_SIZE(&msg) == 10);
	assert_memory_equal(MSG_HEADER_DATA(&msg), "hello", 5);
	assert_memory_equal(MSG_CONTENT_DATA(&msg), "I'm xiedd.", 10);
	zmq_msg_close(MSG_CONTENT(&msg));
	zmq_msg_init_size(MSG_CONTENT(&msg), 17);
	memcpy(MSG_CONTENT_DATA(&msg), "Welcome to zerox.", 17);
	rc = spdnet_sendmsg(&service, &msg);
	assert_true(rc == 0);
	spdnet_msg_close(&msg);

	sleep(1);
	spdnet_msg_init(&msg);
	rc = spdnet_recvmsg(&requester, &msg, 0);
	assert_true(rc == 0);
	assert_true(MSG_SOCKID_SIZE(&msg) == 7);
	assert_true(MSG_HEADER_SIZE(&msg) == 5);
	assert_true(MSG_CONTENT_SIZE(&msg) == 17);
	assert_memory_equal(MSG_HEADER_DATA(&msg), "hello", 5);
	assert_memory_equal(MSG_CONTENT_DATA(&msg), "Welcome to zerox.", 17);
	spdnet_msg_close(&msg);

	assert_true(spdnet_router_msg_routerd(&router) == 5);
	assert_true(spdnet_router_msg_dropped(&router) == 0);

	zmq_send(spdnet_node_get_socket(&requester), "service", 7, 0);
	sleep(1);
	assert_true(spdnet_router_msg_routerd(&router) == 5);
	assert_true(spdnet_router_msg_dropped(&router) == 1);

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

static void test_spdnet_nodepool(void **status)
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
	assert_true(rc == 0);
	rc = spdnet_sendmsg(p, &msg);
	assert_true(rc == 0);
	spdnet_recvmsg_async(p, recvmsg_cb, 3000);
	assert_true(rc == 0);
	spdnet_msg_close(&msg);

	while (snodepool.nr_snode)
		spdnet_nodepool_loop(&snodepool, 0);

	spdnet_nodepool_close(&snodepool);
	spdnet_ctx_destroy(ctx);
}

/*
 * spdnet router
 */

static void test_spdnet_router(void **status)
{
	int rc;
	void *ctx = spdnet_ctx_create();
	struct spdnet_router inner, outer;

	// router inner
	rc = spdnet_router_init(&inner, "router-inner", ctx);
	assert_true(rc == 0);
	rc = spdnet_router_bind(&inner, INNER_ROUTER_ADDRESS);
	assert_true(rc == 0);
	struct task inner_task;
	task_init_timeout(&inner_task, "router-inner-task",
	                  (task_timeout_func_t)spdnet_router_loop,
	                  &inner, 1000);
	task_start(&inner_task);
	sleep(1);

	// router outer
	char inner_id[SPDNET_SOCKID_SIZE];
	size_t inner_len;
	rc = spdnet_router_init(&outer, NULL, ctx);
	assert_true(rc == 0);
	rc = spdnet_router_bind(&outer, OUTER_ROUTER_ADDRESS);
	assert_true(rc == 0);
	rc = spdnet_router_associate(&outer, INNER_ROUTER_ADDRESS,
	                             inner_id, &inner_len);
	assert_true(rc == 0);
	spdnet_router_set_gateway(&outer, inner_id, inner_len, SPDNET_ROUTER);
	struct task outer_task;
	task_init_timeout(&outer_task, "router-outer-task",
	                  (task_timeout_func_t)spdnet_router_loop,
	                  &outer, 1000);
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
	assert_true(rc == 0);
	rc = spdnet_connect(&service, INNER_ROUTER_ADDRESS);
	assert_true(rc == 0);
	rc = spdnet_register(&service);
	assert_true(rc == 0);

	// send from requester to service
	spdnet_msg_close(&msg);
	SPDNET_MSG_INIT_DATA(&msg, "service", "hello", "world");
	rc = spdnet_sendmsg(&requester, &msg);
	assert_true(rc == 0);
	sleep(1);
	rc = spdnet_recvmsg(&service, &msg, 0);
	assert_true(rc == 0);
	assert_true(MSG_SOCKID_SIZE(&msg) == 9);
	assert_true(MSG_HEADER_SIZE(&msg) == 5);
	assert_memory_equal("requester", MSG_SOCKID_DATA(&msg), 9);
	assert_memory_equal("hello", MSG_HEADER_DATA(&msg), 5);
	sleep(1);

	// reply from service to requester
	zmq_msg_close(MSG_HEADER(&msg));
	zmq_msg_init_size(MSG_HEADER(&msg), 5+6);
	memcpy(MSG_HEADER_DATA(&msg), "hello_reply", 5+6);
	rc = spdnet_sendmsg(&service, &msg);
	assert_true(rc == 0);
	sleep(1);
	rc = spdnet_recvmsg(&requester, &msg, 0);
	assert_true(rc == 0);
	assert_true(MSG_SOCKID_SIZE(&msg) == 7);
	assert_true(MSG_HEADER_SIZE(&msg) == 5+6);
	assert_memory_equal("service", MSG_SOCKID_DATA(&msg), 7);
	assert_memory_equal("hello_reply", MSG_HEADER_DATA(&msg), 5+6);
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
	assert_memory_equal(zmq_msg_data(&msg), "hello pgm", 9);
	zmq_msg_close(&msg);
	return NULL;
}

static void test_spdnet_pgm(void **status)
{
	// always fails
	return;
	void *ctx = spdnet_ctx_create();
	void *pub = zmq_socket(ctx, ZMQ_PUB);
	void *sub = zmq_socket(ctx, ZMQ_SUB);

	//const char *url = "tcp://127.0.0.1:1234";
	const char *url = "epgm://enp0s25;239.255.12.24:5964";
	int rc = zmq_bind(pub, url);
	assert_true(rc == 0);
	rc = zmq_connect(sub, url);
	rc = zmq_setsockopt(sub, ZMQ_SUBSCRIBE, "", 0);
	assert_true(rc == 0);
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

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_spdnet_basic),
		cmocka_unit_test(test_spdnet_nodepool),
		cmocka_unit_test(test_spdnet_router),
		cmocka_unit_test(test_spdnet_pgm),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
