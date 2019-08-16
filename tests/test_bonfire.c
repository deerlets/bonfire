#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <unistd.h>
#include <task.h>
#include <bonfire.h>

#define ROUTER_ADDRESS "tcp://127.0.0.1:8338"
#define SERVER_SOCKID "server-sockid"
#define CLIENT_SOCKID "client-sockid"

static int exit_flag;

static void on_hello(struct bonfire_msg *bm)
{
}

static void on_world(struct bonfire_msg *bm)
{
}

static void on_zerox(struct bonfire_msg *bm)
{
	char welcome[] = "Welcome to zerox.";

	bonfire_msg_write_response(bm, welcome, -1);
}

static struct bonfire_service_info services[] = {
	INIT_SERVICE("test://hello", on_hello, ""),
	INIT_SERVICE("test://world", on_world, ""),
	INIT_SERVICE("test://zerox/t", on_zerox, ""),
	INIT_SERVICE(NULL, NULL, NULL),
};

void zerox_cb(const void *resp, size_t len, void *arg, int flag)
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

	struct bonfire *bf = bonfire_new(
		ROUTER_ADDRESS, SERVER_SOCKID, CLIENT_SOCKID);

	bonfire_set_local_services(bf, services);
	assert_true(bonfire_servsync(bf) == 0);
	bonfire_servcall_async(bf, "test://zerox/t", "hello", zerox_cb, bf, 0);

	while (!exit_flag)
		bonfire_loop(bf, 1000);

	bonfire_destroy(bf);

	// server fini
	task_stop(bonfire_server_task);
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
