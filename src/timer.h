#ifndef __ZERO_TIMER_H
#define __ZERO_TIMER_H

#include <stdint.h>
#include <pthread.h>
#include <sys/time.h>
#include "list.h"

#ifdef __cplusplus
extern "C" {
#endif

struct timer;
typedef int (*timer_handler_func_t)(struct timer *timer);

struct timer {
	timer_handler_func_t handler;
	void *arg;
	struct timeval timeout;
	struct timeval repeat;
	pthread_t tid;
	struct list_head node;
};

// timeout & repeat: millisecond
int set_timer(struct timer *timer, timer_handler_func_t handler,
              void *arg, uint64_t timeout, uint64_t repeat);
int kill_timer(struct timer *timer);

int timers_init();
int timers_close();
int timers_run();

#ifdef __cplusplus
}
#endif
#endif
