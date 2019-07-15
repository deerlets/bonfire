#include <unistd.h>
#include <gtest/gtest.h>
#include "service.h"
#include "task.h"

#define ROUTER_ADDRESS "tcp://127.0.0.1:8338"

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
	INIT_SERVICE("hello", on_hello, NULL),
	INIT_SERVICE("world", on_world, NULL),
	INIT_SERVICE("zerox", on_zerox, NULL),
	INIT_SERVICE(NULL, NULL, NULL),
};

TEST(service, servarea)
{
	struct servarea sa;
	servarea_init(&sa, "testing");
	servarea_register_services(&sa, services);

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
	task_init_timeout(&router_task, "router_task",
	                  (task_timeout_func_t)spdnet_router_loop, &router, 500);
	task_start(&router_task);

	// init servhub
	struct spdnet_nodepool snodepool;
	spdnet_nodepool_init(&snodepool, 20, ctx);
	struct servhub servhub;
	servhub_init(&servhub, "servhub", ROUTER_ADDRESS, &snodepool);
	struct task servhub_task;
	task_init_timeout(&servhub_task, "servhub_task",
	                  (task_timeout_func_t)servhub_loop, &servhub, 500);
	task_start(&servhub_task);

	// wait for tasks
	sleep(1);

	// client & msg
	struct spdnet_node client;
	struct spdnet_msg msg;

	// init service
	servhub_register_servarea(&servhub, "testing", services, NULL, NULL);
	// start testing
	spdnet_node_init(&client, SPDNET_NODE, ctx);
	spdnet_connect(&client, ROUTER_ADDRESS);
	SPDNET_MSG_INIT_DATA(&msg, "servhub", "testing://zerox/t", "I'm xiedd.");
	spdnet_sendmsg(&client, &msg);
	sleep(1);
	spdnet_recvmsg(&client, &msg, 0);
	ASSERT_EQ(MSG_SOCKID_SIZE(&msg), 7);
	ASSERT_EQ(MSG_HEADER_SIZE(&msg), 17+6);
	ASSERT_EQ(memcmp(MSG_HEADER_DATA(&msg),
	                 "testing://zerox/t_reply", 17+6), 0);
	ASSERT_NE(strstr((char *)MSG_CONTENT_DATA(&msg),
	                 "Welcome to zerox."), nullptr);
	spdnet_msg_close(&msg);
	spdnet_node_close(&client);
	// close service
	servhub_unregister_servarea(&servhub, "testing", NULL);

	// init service
	servhub_register_servarea(&servhub, "testing2", services,
	                          "testing2-sockid", NULL);
	// start testing2
	spdnet_node_init(&client, SPDNET_NODE, ctx);
	spdnet_connect(&client, ROUTER_ADDRESS);
	SPDNET_MSG_INIT_DATA(&msg, "testing2-sockid",
	                     "testing2://zerox/t", "I'm xiedd.");
	spdnet_sendmsg(&client, &msg);
	sleep(1);
	spdnet_recvmsg(&client, &msg, 0);
	ASSERT_EQ(MSG_SOCKID_SIZE(&msg), 15);
	ASSERT_EQ(MSG_HEADER_SIZE(&msg), 18+6);
	ASSERT_EQ(memcmp(MSG_HEADER_DATA(&msg),
	                 "testing2://zerox/t_reply", 18+6), 0);
	ASSERT_NE(strstr((char *)MSG_CONTENT_DATA(&msg),
	                 "Welcome to zerox."), nullptr);
	spdnet_msg_close(&msg);
	spdnet_node_close(&client);
	// close service
	servhub_unregister_servarea(&servhub, "testing2", "testing2-sockid");

	// close servhub
	task_stop(&servhub_task);
	task_close(&servhub_task);
	servhub_close(&servhub);
	spdnet_nodepool_close(&snodepool);

	// close spdnet router
	task_stop(&router_task);
	task_close(&router_task);
	spdnet_router_close(&router);
	spdnet_ctx_destroy(ctx);
}
