#ifndef __EXT_TASK_H
#define __EXT_TASK_H

#ifdef __cplusplus
extern "C" {
#endif

#define TASK_NAME_LEN 64

enum task_type {
    TASK_T_RUN = 0,
    TASK_T_TIMEOUT,
};

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
typedef int (*task_timeout_func_t)(void *, long timeout);

struct task;

struct task *task_new(const char *name, task_run_func_t fn, void *arg);
struct task *task_new_timeout(const char *name, task_timeout_func_t fn,
                              void *arg, long timeout);
void task_destroy(struct task *t);
int task_start(struct task *t);
void task_stop(struct task *t);
#ifndef __APPLE__
void task_suspend(struct task *t);
void task_resume(struct task *t);
#endif
int task_state(struct task *t);

#ifdef __cplusplus
}
#endif
#endif
