#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/time.h>
#include "extlist.h"
#include "timer.h"

struct timer {
	timer_handler_func_t handler;
	void *arg;

	// timeout & repeat: millisecond
	struct timeval timeout;
	struct timeval repeat;

	struct timer_loop *loop;
	struct list_head node;
};

struct timer_loop {
	pthread_t pid;
	struct list_head node;
	struct list_head timers;
};

static LIST_HEAD(_loops);

static struct timer_loop *timer_loop_new()
{
	struct timer_loop *loop = malloc(sizeof(*loop));
	if (!loop) return NULL;
	memset(loop, 0, sizeof(*loop));

	loop->pid = pthread_self();
	INIT_LIST_HEAD(&loop->node);
	INIT_LIST_HEAD(&loop->timers);

	return loop;
}

static void timer_loop_destroy(struct timer_loop *loop)
{
	assert(list_empty(&loop->timers));
	list_del(&loop->node);
	free(loop);
}

static struct timer_loop *find_timer_loop(pthread_t pid)
{
	struct timer_loop *pos;
	list_for_each_entry(pos, &_loops, node) {
		if (pos->pid == pid)
			return pos;
	}
	return NULL;
}

struct timer *timer_new()
{
	struct timer_loop *loop = find_timer_loop(pthread_self());
	if (!loop) {
		loop = timer_loop_new();
		list_add(&loop->node, &_loops);
	}

	struct timer *timer = malloc(sizeof(*timer));
	if (!timer) return NULL;
	memset(timer, 0, sizeof(*timer));

	timer->loop = loop;
	INIT_LIST_HEAD(&timer->node);
	list_add(&timer->node, &timer->loop->timers);

	return timer;
}

void timer_destroy(struct timer *timer)
{
	assert(pthread_self() == timer->loop->pid);
	list_del(&timer->node);
	if (list_empty(&timer->loop->timers))
		timer_loop_destroy(timer->loop);
	free(timer);
}

void timer_start(struct timer *timer, timer_handler_func_t handler,
                 void *arg, uint64_t timeout, uint64_t repeat)
{
	assert(pthread_self() == timer->loop->pid);
	timer->handler = handler;
	timer->arg = arg;
	timerclear(&timer->timeout);
	struct timeval now;
	gettimeofday(&now, NULL);
	timer->timeout.tv_sec = now.tv_sec + timeout / 1000;
	timer->timeout.tv_usec = now.tv_usec + timeout % 1000 * 1000;
	timer->repeat.tv_sec = repeat / 1000;
	timer->repeat.tv_usec = repeat % 1000 * 1000;
}

void timer_stop(struct timer *timer)
{
	assert(pthread_self() == timer->loop->pid);
	timer->handler = NULL;
	timer->arg = 0;
	timer->timeout.tv_sec = 0;
	timer->timeout.tv_usec = 0;
	timer->repeat.tv_sec = 0;
	timer->repeat.tv_usec = 0;
}

void timer_trigger(struct timer *timer)
{
	assert(pthread_self() == timer->loop->pid);
	gettimeofday(&timer->timeout, NULL);
}

int timer_loop(long *next)
{
	struct timer_loop *loop = find_timer_loop(pthread_self());
	assert(loop);

	struct timeval now, _next;
	gettimeofday(&now, NULL);
	_next = now;
	_next.tv_sec += 1;

	struct timer *pos, *n;
	list_for_each_entry_safe(pos, n, &loop->timers, node) {
		if (!timerisset(&pos->timeout)) continue;

		if (timercmp(&pos->timeout, &now, >)) {
			if (timercmp(&pos->timeout, &_next, <))
				_next = pos->timeout;
			continue;
		}

		// calculate new timeout & _next
		if (!timerisset(&pos->repeat)) {
			timerclear(&pos->timeout);
		} else {
			do {
				timeradd(&pos->timeout, &pos->repeat,
				         &pos->timeout);
			} while (timercmp(&pos->timeout, &now, <));

			if (timercmp(&pos->timeout, &_next, <))
				_next = pos->timeout;
		}

		// call handler
		pos->handler(pos, pos->arg);

		/*
		 * do nothing after call handler as current timer
		 * will be killed in handler
		 */
	}

	if (next) {
		gettimeofday(&now, NULL);
		if (timercmp(&_next, &now, >))
			*next = (_next.tv_sec - now.tv_sec) * 1000 +
				(_next.tv_usec - now.tv_usec) / 1000;
		else
			*next = 0;
	}

	return 0;
}
