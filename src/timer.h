#ifndef __ZEBRA_TIMER_H
#define __ZEBRA_TIMER_H

#include <stdint.h>
#include <pthread.h>
#include <sys/time.h>
#include <spdnet/list.h>
#include <spdnet/mutex.h>

#ifdef __cplusplus
extern "C" {
#endif

struct timer;
struct timer_loop;

typedef int (*timer_handler_func_t)(struct timer *timer);

struct timer {
	timer_handler_func_t handler;
	void *arg;

	// timeout & repeat: millisecond
	struct timeval timeout;
	struct timeval repeat;

	struct timer_loop *loop;
	struct list_head node;
};

int timer_init(struct timer *timer, struct timer_loop *loop);
int timer_close(struct timer *timer);
void timer_start(struct timer *timer, timer_handler_func_t handler,
                 void *arg, uint64_t timeout, uint64_t repeat);
void timer_stop(struct timer *timer);
void timer_trigger(struct timer *timer);

struct timer_loop {
	struct list_head timers;
	pthread_mutex_t timers_lock;
};

int timer_loop_init(struct timer_loop *loop);
int timer_loop_close(struct timer_loop *loop);
int timer_loop_run(struct timer_loop *loop, struct timeval *next);

struct timer_loop *default_timer_loop(void);

#ifdef __cplusplus
}
#endif
#endif
