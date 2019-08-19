#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <unistd.h>
#include <task.h>
#include <bonfire.h>

#define ROUTER_ADDRESS "tcp://127.0.0.1:8338"
#define SERVER_SOCKID "server-sockid"
#define HELLO_CLIENT_SOCKID "hello-client-sockid"
#define ZEROX_CLIENT_SOCKID "zerox-client-sockid"

static int exit_flag;

static void on_hello(struct bmsg *bm)
{
}

static void on_world(struct bmsg *bm)
{
}

static struct bonfire_service_info services_hello[] = {
	INIT_SERVICE("test://hello", on_hello),
	INIT_SERVICE("test://world", on_world),
	INIT_SERVICE(NULL, NULL),
};

static void on_zerox(struct bmsg *bm)
{
	char welcome[] = "Welcome to zerox.";

	bmsg_write_response(bm, welcome);
}

static struct bonfire_service_info services_zerox[] = {
	INIT_SERVICE("test://zerox/t", on_zerox),
	INIT_SERVICE(NULL, NULL),
};

void hello_to_zerox_cb(const void *resp, size_t len, void *arg, int flag)
{
	assert_true(flag == BONFIRE_SERVCALL_OK);

	assert_true(len == 17);
	assert_memory_equal(resp, "Welcome to zerox.", 17);

	exit_flag = 1;
}

static void test_bonfire(void **status)
{
	// server init
	struct bonfire_server *server =
		bonfire_server_new(ROUTER_ADDRESS, SERVER_SOCKID);
	struct task *bonfire_server_task = task_new_timeout(
		"bonfire-server-task",
		(task_timeout_func_t)bonfire_server_loop,
		server, 500);
	task_start(bonfire_server_task);

	// hello client init
	struct bonfire *bf_hello = bonfire_new(
		ROUTER_ADDRESS, SERVER_SOCKID, HELLO_CLIENT_SOCKID);
	bonfire_set_local_services(bf_hello, services_hello);
	assert_true(bonfire_servsync(bf_hello) == 0);

	// zerox client init
	struct bonfire *bf_zerox = bonfire_new(
		ROUTER_ADDRESS, SERVER_SOCKID, ZEROX_CLIENT_SOCKID);
	bonfire_set_local_services(bf_zerox, services_zerox);
	assert_true(bonfire_servsync(bf_zerox) == 0);
	struct task *bf_zerox_task = task_new_timeout(
		"bf_zerox_task",
		(task_timeout_func_t)bonfire_loop,
		bf_zerox, 500);
	task_start(bf_zerox_task);

	// wait for zerox to sync services
	sleep(1);
	//if (bonfire_servcall(bf_hello, "test://zerox/t", "hello", NULL) == 0)
	//	exit_flag = 1;
	bonfire_servcall_async(bf_hello, "test://zerox/t", "hello",
	                       hello_to_zerox_cb, bf_hello);

	// hello client loop
	while (!exit_flag)
		bonfire_loop(bf_hello, 1000);

	// hello client fini
	bonfire_destroy(bf_hello);

	// zerox client fini
	task_destroy(bf_zerox_task);
	bonfire_destroy(bf_zerox);

	// server fini
	task_destroy(bonfire_server_task);
	bonfire_server_destroy(server);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_bonfire),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
