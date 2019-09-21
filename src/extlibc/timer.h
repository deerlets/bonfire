#ifndef __EXT_TIMER_H
#define __EXT_TIMER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct timer;
typedef void (*timer_handler_func_t)(struct timer *timer, void *arg);

struct timer *timer_new();
void timer_destroy(struct timer *timer);
void timer_start(struct timer *timer, timer_handler_func_t handler,
                 void *arg, uint64_t timeout, uint64_t repeat);
void timer_stop(struct timer *timer);
void timer_trigger(struct timer *timer);

int timer_loop(long *next);

#ifdef __cplusplus
}
#endif
#endif
