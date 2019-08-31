#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <unistd.h>
#include <task.h>
#include <bonfire.h>

#define BROKER_ADDRESS "tcp://127.0.0.1:8338"
#define FWD_PUB_ADDRESS "tcp://127.0.0.1:9338"
#define FWD_SUB_ADDRESS "tcp://127.0.0.1:9339"

#define BROKER_SOCKID "broker-sockid"
#define HELLO_CLIENT_SOCKID "hello-client-sockid"
#define ZEROX_CLIENT_SOCKID "zerox-client-sockid"
#define PUB_CLIENT_SOCKID "pub-client-sockid"
#define SUB_CLIENT_SOCKID "sub-client-sockid"

static int exit_flag;

static void on_hello(struct bmsg *bm)
{
}

static void on_world(struct bmsg *bm)
{
}

static void on_zerox(struct bmsg *bm)
{
	char welcome[] = "Welcome to zerox.";

	bmsg_write_response(bm, welcome);
}

static void noserv_cb(struct bonfire *bf, const void *resp,
                      size_t len, void *arg, int flag)
{
	assert_true(flag == BONFIRE_ENOSERV);
}

static void hello_to_zerox_cb(struct bonfire *bf, const void *resp,
                              size_t len, void *arg, int flag)
{
	assert_true(flag == BONFIRE_EOK);

	assert_true(len == 17);
	assert_memory_equal(resp, "Welcome to zerox.", 17);

	exit_flag = 1;
}

static void test_bonfire_servcall(void **status)
{
	// bbrk init
	struct bonfire_broker *bbrk = bonfire_broker_new(
		BROKER_ADDRESS, FWD_PUB_ADDRESS, FWD_SUB_ADDRESS);
	struct task *bonfire_broker_task = task_new_timeout(
		"bonfire-bbrk-task",
		(task_timeout_func_t)bonfire_broker_loop,
		bbrk, 500);
	task_start(bonfire_broker_task);

	// hello client init
	struct bonfire *bf_hello = bonfire_new();
	bonfire_connect(bf_hello, BROKER_ADDRESS);
	bonfire_add_service(bf_hello, "test://hello", on_hello);
	bonfire_add_service(bf_hello, "test://world", on_world);

	// zerox client init
	struct bonfire *bf_zerox = bonfire_new();
	bonfire_connect(bf_zerox, BROKER_ADDRESS);
	bonfire_add_service(bf_zerox, "test://zerox/t", on_zerox);
	struct task *bf_zerox_task = task_new_timeout(
		"bf_zerox_task",
		(task_timeout_func_t)bonfire_loop,
		bf_zerox, 500);
	task_start(bf_zerox_task);

	// wait for zerox to sync services
	sleep(1);
	//if (bonfire_servcall(bf_hello, "test://zerox/t", "hello", NULL) == 0)
	//	exit_flag = 1;
	bonfire_servcall_async(bf_hello, "test://zerox", "hello",
	                       noserv_cb, bf_hello);
	bonfire_servcall_async(bf_hello, "test://zerox/t", "hello",
	                       hello_to_zerox_cb, bf_hello);

	// hello client loop
	exit_flag = 0;
	while (!exit_flag)
		bonfire_loop(bf_hello, 1000);

	// hello client fini
	bonfire_destroy(bf_hello);

	// zerox client fini
	task_destroy(bf_zerox_task);
	bonfire_destroy(bf_zerox);

	// bbrk fini
	task_destroy(bonfire_broker_task);
	bonfire_broker_destroy(bbrk);
}

static void subscribe_cb(struct bonfire *bf, const void *resp,
                         size_t len, void *arg, int flag)
{
	if (flag != BONFIRE_EOK) {
		assert_true(resp == NULL);
		assert_true(len == 0);
		return;
	}

	assert_true(len == 5);
	assert_memory_equal(resp, "hello", len);
	exit_flag = 1;
}

static void test_bonfire_pub_sub(void **status)
{
	// bbrk init
	struct bonfire_broker *bbrk = bonfire_broker_new(
		BROKER_ADDRESS, FWD_PUB_ADDRESS, FWD_SUB_ADDRESS);
	struct task *bonfire_broker_task = task_new_timeout(
		"bonfire-bbrk-task",
		(task_timeout_func_t)bonfire_broker_loop,
		bbrk, 500);
	task_start(bonfire_broker_task);

	// sub client init
	struct bonfire *bf_sub = bonfire_new();
	bonfire_connect(bf_sub, BROKER_ADDRESS);
	bonfire_subscribe(bf_sub, "topic-test", subscribe_cb, NULL);

	// pub client init
	struct bonfire *bf_pub = bonfire_new();
	bonfire_connect(bf_pub, BROKER_ADDRESS);
	sleep(1);
	bonfire_publish(bf_pub, "topic-test", "hello");

	// sub client loop
	exit_flag = 0;
	while (!exit_flag)
		bonfire_loop(bf_sub, 1000);

	// sub client fini
	bonfire_unsubscribe(bf_sub, "topic-test");
	bonfire_destroy(bf_sub);

	// pub client fini
	bonfire_destroy(bf_pub);

	// bbrk fini
	task_destroy(bonfire_broker_task);
	bonfire_broker_destroy(bbrk);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_bonfire_servcall),
		cmocka_unit_test(test_bonfire_pub_sub),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
