#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <unistd.h>
#include "service.h"
#include "task.h"

#define ROUTER_ADDRESS "tcp://127.0.0.1:8338"

static void on_hello(struct servmsg *sm)
{
}

static void on_world(struct servmsg *sm)
{
}

static void on_zerox(struct servmsg *sm)
{
	char welcome[] = "Welcome to zerox.";

	servmsg_respcnt_reset_data(sm, welcome, -1);
}

static struct service services[] = {
	INIT_SERVICE("hello", on_hello, NULL),
	INIT_SERVICE("world", on_world, NULL),
	INIT_SERVICE("zerox", on_zerox, NULL),
	INIT_SERVICE(NULL, NULL, NULL),
};

static void test_servarea(void **status)
{
	struct servarea sa;
	servarea_init(&sa, "testing");
	servarea_register_services(&sa, services);

	struct service *serv;
	serv = __servarea_find_service(&sa, "hello");
	assert_true(serv);
	assert_string_equal(serv->name, "hello");

	assert_true(serv->handler == on_hello);
	assert_true(__servarea_find_handler(&sa, "hello") == on_hello);

	for (size_t i = 0; i < sizeof(services)/sizeof(struct service) - 1; i++)
		servarea_unregister_service(&sa, services + i);

	assert_true(__servarea_find_service(&sa, "hello") == NULL);
	assert_true(__servarea_find_handler(&sa, "hello") == NULL);

	servarea_close(&sa);
}

static void test_servhub(void **status)
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
	assert_true(MSG_SOCKID_SIZE(&msg) == 7);
	assert_true(MSG_HEADER_SIZE(&msg) == 17+6);
	assert_memory_equal(MSG_HEADER_DATA(&msg),
	                    "testing://zerox/t#reply", 17+6);
	assert_memory_equal(MSG_CONTENT_DATA(&msg), "Welcome to zerox.", 17);
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
	assert_true(MSG_SOCKID_SIZE(&msg) == 15);
	assert_true(MSG_HEADER_SIZE(&msg) == 18+6);
	assert_memory_equal(MSG_HEADER_DATA(&msg),
	                    "testing2://zerox/t#reply", 18+6);
	assert_memory_equal(MSG_CONTENT_DATA(&msg), "Welcome to zerox.", 17);
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

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_servarea),
		cmocka_unit_test(test_servhub),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
