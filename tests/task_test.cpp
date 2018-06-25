#include <unistd.h>
#include <gtest/gtest.h>
#include "task.h"

static int loop_test(void *arg)
{
	sleep(1);
	return 0;
}

TEST(task, basic)
{
	struct task task;
	task_init(&task, "task_test", loop_test, NULL);
	assert(task.t_state == TASK_S_PENDING);
	task_start(&task);
	sleep(1);
	assert(task.t_state == TASK_S_RUNNING);
#ifndef __APPLE__
	task_suspend(&task);
	sleep(2);
	assert(task.t_state == TASK_S_PENDING);
	task_resume(&task);
	sleep(6);
	assert(task.t_state == TASK_S_RUNNING);
#endif
	task_stop(&task);
	assert(task.t_state == TASK_S_STOPPED);
	task_close(&task);
}
