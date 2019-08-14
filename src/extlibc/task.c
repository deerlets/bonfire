#include "task.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef __unix
#include <sys/prctl.h>
#endif

static void *task_routine(void *arg)
{
	struct task *t = (struct task *)arg;
#ifdef __unix
	prctl(PR_SET_NAME, t->t_name, NULL, NULL, NULL);
#endif
	t->t_state = TASK_S_RUNNING;

	while (1) {
		if (t->t_control == TASK_C_STOP)
			break;

		if (t->t_control == TASK_C_RESUME) {
			t->t_state = TASK_S_RUNNING;
			t->t_control = TASK_C_NONE;
		}

		if (t->t_control == TASK_C_SUSPEND) {
			t->t_state = TASK_S_PENDING;
			sleep(5);
			continue;
		}

		if (t->t_type == TASK_T_RUN) {
			if (t->t_fn.run_fn(t->t_arg))
				break;
		} else {
			if (t->t_fn.timeout_fn(t->t_arg, t->t_timeout))
				break;
		}
	}

	return NULL;
}

int task_init(struct task *t, const char *name, task_run_func_t fn, void *arg)
{
	memset(t, 0, sizeof(*t));

	t->t_id = 0;
	snprintf(t->t_name, TASK_NAME_LEN, "%s", name);
	t->t_state = TASK_S_PENDING;
	t->t_control = TASK_C_NONE;

	t->t_type = TASK_T_RUN;
	t->t_fn.run_fn = fn;
	t->t_arg = arg;
	t->t_timeout = 0;

	INIT_LIST_HEAD(&t->t_node);
	return 0;
}

int task_init_timeout(struct task *t, const char *name, task_timeout_func_t fn,
                      void *arg, long timeout)
{
	memset(t, 0, sizeof(*t));

	t->t_id = 0;
	snprintf(t->t_name, TASK_NAME_LEN, "%s", name);
	t->t_state = TASK_S_PENDING;
	t->t_control = TASK_C_NONE;

	t->t_type = TASK_T_TIMEOUT;
	t->t_fn.timeout_fn = fn;
	t->t_arg = arg;
	t->t_timeout = timeout;

	INIT_LIST_HEAD(&t->t_node);
	return 0;
}

int task_close(struct task *t)
{
	if (t->t_state != TASK_S_STOPPED)
		return -1;
	return 0;
}

int task_start(struct task *t)
{
	return pthread_create(&t->t_id, NULL, task_routine, t);
}

int task_stop(struct task *t)
{
	t->t_control = TASK_C_STOP;
	pthread_join(t->t_id, NULL);
	t->t_state = TASK_S_STOPPED;
	return 0;
}

#ifndef __APPLE__
void task_suspend(struct task *t)
{
	assert(t->t_state == TASK_S_RUNNING);
	t->t_control = TASK_C_SUSPEND;
}
#endif

#ifndef __APPLE__
void task_resume(struct task *t)
{
	assert(t->t_state == TASK_S_PENDING);
	t->t_control = TASK_C_RESUME;
}
#endif

int task_state(struct task *t)
{
	return t->t_state;
}
