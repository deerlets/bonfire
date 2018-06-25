#ifndef __ZERO_TASK_H
#define __ZERO_TASK_H

#include <pthread.h>
#include "list.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TASK_NAME_LEN 64

enum task_state {
	TASK_S_PENDING = 0,
	TASK_S_RUNNING = 1,
	TASK_S_STOPPED = 2,
};

enum task_control {
	TASK_C_NONE = 0,
	TASK_C_SUSPEND = 1,
	TASK_C_RESUME = 2,
	TASK_C_STOP = 3,
};

typedef int (*task_run_func_t)(void *);

struct task {
	pthread_t t_id;
	char t_name[TASK_NAME_LEN];
	int t_state;
	int t_control;

	task_run_func_t t_run_fn;
	void *t_arg;
	struct list_head t_node;
};

int task_init(struct task *t, const char *name, int (*run)(void *), void *arg);
int task_close(struct task *t);
int task_start(struct task *t);
int task_stop(struct task *t);
#ifndef __APPLE__
void task_suspend(struct task *t);
void task_resume(struct task *t);
#endif
int task_state(struct task *t);

#ifdef __cplusplus
}
#endif
#endif
