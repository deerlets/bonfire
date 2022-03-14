#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include "task.h"

struct task {
    pthread_t t_id;
    char t_name[TASK_NAME_LEN];
    int t_state;
    int t_control;

    int t_type;
    union {
        task_run_func_t run_fn;
        task_timeout_func_t timeout_fn;
    } t_fn;
    void *t_arg;
    long t_timeout;
};

static void *task_routine(void *arg)
{
    struct task *t = (struct task *)arg;
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

struct task *task_new(const char *name, task_run_func_t fn, void *arg)
{
    struct task *t = malloc(sizeof(*t));
    if (!t) return NULL;
    memset(t, 0, sizeof(*t));

    t->t_id = 0;
    snprintf(t->t_name, TASK_NAME_LEN, "%s", name);
    t->t_state = TASK_S_PENDING;
    t->t_control = TASK_C_NONE;

    t->t_type = TASK_T_RUN;
    t->t_fn.run_fn = fn;
    t->t_arg = arg;
    t->t_timeout = 0;

    return t;
}

struct task *task_new_timeout(const char *name, task_timeout_func_t fn,
                              void *arg, long timeout)
{
    struct task *t = task_new(name, NULL, arg);
    if (!t) return NULL;

    t->t_type = TASK_T_TIMEOUT;
    t->t_fn.timeout_fn = fn;
    t->t_timeout = timeout;

    return t;
}

void task_destroy(struct task *t)
{
    if (t->t_state != TASK_S_STOPPED)
        task_stop(t);
    free(t);
}

int task_start(struct task *t)
{
    return pthread_create(&t->t_id, NULL, task_routine, t);
}

void task_stop(struct task *t)
{
    t->t_control = TASK_C_STOP;
    pthread_join(t->t_id, NULL);
    t->t_state = TASK_S_STOPPED;
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
