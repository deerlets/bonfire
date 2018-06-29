#include <unistd.h>
#include <gtest/gtest.h>
#include "service.h"
#include "task.h"
#include "utils.h"

#define ROUTER_ADDRESS "tcp://127.0.0.1:8338"
#define SERVHUB_PUBLISH_ADDRESS "inproc://servhub-publish"
#define SERVHUB_MULTICAST_IP "239.255.12.24"
#define SERVHUB_MULTICAST_PORT 5964

static int on_hello(struct servmsg *sm)
{
	return 0;
}

static int on_world(struct servmsg *sm)
{
	return 0;
}

static int on_zerox(struct servmsg *sm)
{
	char welcome[] = "Welcome to zerox.";

	servmsg_respcnt_reset_data(sm, welcome, -1);
	return 0;
}

static struct service services[] = {
	SERVICE_INIT("hello", on_hello, NULL),
	SERVICE_INIT("world", on_world, NULL),
	SERVICE_INIT("zerox", on_zerox, NULL),
	SERVICE_INIT(NULL, NULL, NULL),
};

TEST(service, servarea)
{
	struct servarea sa;
	servarea_init(&sa, "testing");
	servarea_register_service_batch(&sa, services);

	struct service *serv;
	serv = __servarea_find_service(&sa, "hello");
	ASSERT_NE(serv, (void *)NULL);
	ASSERT_STREQ(serv->name, "hello");

	// ASSERT_EQ failed when comparing functions on Darwin
	assert(serv->handler == on_hello);
	assert(__servarea_find_handler(&sa, "hello") == on_hello);

	for (size_t i = 0; i < sizeof(services)/sizeof(struct service) - 1; i++)
		servarea_unregister_service(&sa, services + i);

	ASSERT_EQ(__servarea_find_service(&sa, "hello"), (void *)NULL);
	ASSERT_EQ(__servarea_find_handler(&sa, "hello"), (void *)NULL);

	servarea_close(&sa);
}

TEST(service, servhub)
{
	// init spdnet router
	void *ctx = spdnet_ctx_create();
	struct spdnet_router router;
	spdnet_router_init(&router, "router_inner", ctx);
	spdnet_router_bind(&router, ROUTER_ADDRESS);
	struct task router_task;
	task_init(&router_task, "router_task",
	          (task_run_func_t)spdnet_router_run, &router);
	task_start(&router_task);

	// init servhub
	char pgm_addr[SPDNET_ADDRESS_SIZE];
	snprintf(pgm_addr, sizeof(pgm_addr), "epgm://%s;%s:%d",
	         get_ifaddr(), SERVHUB_MULTICAST_IP, SERVHUB_MULTICAST_PORT);
	struct spdnet_nodepool serv_snodepool;
	struct spdnet_nodepool req_snodepool;
	struct spdnet_node spublish;
	struct spdnet_multicast smulticast;
	spdnet_nodepool_init(&serv_snodepool, 20, ctx);
	spdnet_nodepool_init(&req_snodepool, 20, ctx);
	spdnet_publish_init(&spublish, SERVHUB_PUBLISH_ADDRESS, ctx);
	spdnet_multicast_init(&smulticast, pgm_addr, 1, ctx);
	struct servhub servhub;
	servhub_init(&servhub, "servhub", ROUTER_ADDRESS,
	             &serv_snodepool, &req_snodepool, &spublish, &smulticast);
	struct task servhub_task;
	task_init(&servhub_task, "servhub_task",
	          (task_run_func_t)servhub_run, &servhub);
	task_start(&servhub_task);

	// init service
	servhub_register_service(&servhub, "testing", services, NULL);

	// wait for tasks
	sleep(1);

	// start testing
	struct spdnet_node client;
	spdnet_node_init(&client, SPDNET_NODE, ctx);
	spdnet_connect(&client, ROUTER_ADDRESS);
	struct spdnet_msg msg;
	SPDNET_MSG_INIT_DATA(&msg, "testing", "zerox", "I'm xiedd.");
	spdnet_sendmsg(&client, &msg);
	sleep(1);
	spdnet_recvmsg(&client, &msg, 0);
	ASSERT_EQ(zmq_msg_size(MSG_SOCKID(&msg)), 7);
	ASSERT_EQ(zmq_msg_size(MSG_HEADER(&msg)), 5+6);
	ASSERT_EQ(memcmp(zmq_msg_data(MSG_HEADER(&msg)), "zerox_reply", 5+6), 0);
	ASSERT_NE(strstr((char *)zmq_msg_data(MSG_CONTENT(&msg)),
	                 "Welcome to zerox."), nullptr);
	spdnet_msg_close(&msg);
	spdnet_node_close(&client);

	// close service
	servhub_unregister_service(&servhub, "testing");

	// close servhub
	task_stop(&servhub_task);
	task_close(&servhub_task);
	servhub_close(&servhub);
	spdnet_nodepool_close(&serv_snodepool);
	spdnet_nodepool_close(&req_snodepool);
	spdnet_multicast_close(&smulticast);

	// close spdnet router
	task_stop(&router_task);
	task_close(&router_task);
	spdnet_router_close(&router);
	spdnet_ctx_destroy(ctx);
}
