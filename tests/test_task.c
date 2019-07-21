#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <unistd.h>
#include "task.h"

static int loop_test(void *arg)
{
	sleep(1);
	return 0;
}

static void test_task(void **status)
{
	struct task task;
	task_init(&task, "task_test", loop_test, NULL);
	assert_true(task.t_state == TASK_S_PENDING);
	task_start(&task);
	sleep(1);
	assert_true(task.t_state == TASK_S_RUNNING);
#ifndef __APPLE__
	task_suspend(&task);
	sleep(2);
	assert_true(task.t_state == TASK_S_PENDING);
	task_resume(&task);
	sleep(6);
	assert_true(task.t_state == TASK_S_RUNNING);
#endif
	task_stop(&task);
	assert_true(task.t_state == TASK_S_STOPPED);
	task_close(&task);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_task),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
