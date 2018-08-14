#include "timer.h"
#include <string.h>

#ifdef __WIN32
/* Convenience macros for operations on timevals.
   NOTE: `timercmp' does not work for >= or <=.  */
# define timerisset(tvp)	((tvp)->tv_sec || (tvp)->tv_usec)
#if 0
# define timerclear(tvp)	((tvp)->tv_sec = (tvp)->tv_usec = 0)
# define timercmp(a, b, CMP)                                          \
  (((a)->tv_sec == (b)->tv_sec) ? 					      \
   ((a)->tv_usec CMP (b)->tv_usec) : 					      \
   ((a)->tv_sec CMP (b)->tv_sec))
#endif
# define timeradd(a, b, result)						      \
  do {									      \
    (result)->tv_sec = (a)->tv_sec + (b)->tv_sec;			      \
    (result)->tv_usec = (a)->tv_usec + (b)->tv_usec;			      \
    if ((result)->tv_usec >= 1000000)					      \
      {									      \
	++(result)->tv_sec;						      \
	(result)->tv_usec -= 1000000;					      \
      }									      \
  } while (0)
# define timersub(a, b, result)						      \
  do {									      \
    (result)->tv_sec = (a)->tv_sec - (b)->tv_sec;			      \
    (result)->tv_usec = (a)->tv_usec - (b)->tv_usec;			      \
    if ((result)->tv_usec < 0) {					      \
      --(result)->tv_sec;						      \
      (result)->tv_usec += 1000000;					      \
    }									      \
  } while (0)
#endif	/* Misc.  */

struct timer_loop *default_timer_loop(void)
{
	static struct timer_loop timer_loop;
	return &timer_loop;
}

int timer_init(struct timer_loop *loop, struct timer *timer)
{
	memset(timer, 0, sizeof(*timer));
	timer->loop = loop;
	INIT_LIST_HEAD(&timer->node);

	if (timer->loop->tid != pthread_self())
		pthread_mutex_lock(&loop->timers_added_lock);

	list_add(&timer->node, &loop->timers_added);

	if (timer->loop->tid != pthread_self())
		pthread_mutex_unlock(&loop->timers_added_lock);

	return 0;
}

int timer_close(struct timer *timer)
{
	if (timer->loop->tid != pthread_self())
		pthread_mutex_lock(&timer->loop->timers_lock);

	list_del(&timer->node);

	if (timer->loop->tid != pthread_self())
		pthread_mutex_unlock(&timer->loop->timers_lock);

	timer->loop = NULL;
	return 0;
}

void timer_start(struct timer *timer, timer_handler_func_t handler,
                 void *arg, uint64_t timeout, uint64_t repeat)
{
	if (timer->loop->tid != pthread_self())
		pthread_mutex_lock(&timer->loop->timers_lock);

	timer->handler = handler;
	timer->arg = arg;
	timer->timeout.tv_sec = time(NULL) + timeout / 1000;
	timer->timeout.tv_usec = timeout % 1000 * 1000;
	timer->repeat.tv_sec = repeat / 1000;
	timer->repeat.tv_usec = repeat % 1000 * 1000;

	if (timer->loop->tid != pthread_self())
		pthread_mutex_unlock(&timer->loop->timers_lock);
}

void timer_stop(struct timer *timer)
{
	if (timer->loop->tid != pthread_self())
		pthread_mutex_lock(&timer->loop->timers_lock);

	timer->handler = NULL;
	timer->arg = 0;
	timer->timeout.tv_sec = 0;
	timer->timeout.tv_usec = 0;
	timer->repeat.tv_sec = 0;
	timer->repeat.tv_usec = 0;

	if (timer->loop->tid != pthread_self())
		pthread_mutex_unlock(&timer->loop->timers_lock);
}

void timer_trigger(struct timer *timer)
{
	if (timer->loop->tid != pthread_self())
		pthread_mutex_lock(&timer->loop->timers_lock);

	gettimeofday(&timer->timeout, NULL);

	if (timer->loop->tid != pthread_self())
		pthread_mutex_unlock(&timer->loop->timers_lock);
}

int timer_loop_init(struct timer_loop *loop)
{
	loop->tid = 0;

	INIT_LIST_HEAD(&loop->timers);
	pthread_mutex_init(&loop->timers_lock, NULL);

	INIT_LIST_HEAD(&loop->timers_added);
	pthread_mutex_init(&loop->timers_added_lock, NULL);

	return 0;
}

int timer_loop_close(struct timer_loop *loop)
{
	if (!list_empty(&loop->timers) || !list_empty(&loop->timers_added))
		return -1;

	pthread_mutex_destroy(&loop->timers_lock);
	pthread_mutex_destroy(&loop->timers_added_lock);

	return 0;
}

int timer_loop_run(struct timer_loop *loop, struct timeval *next)
{
	struct timeval now;
	gettimeofday(&now, NULL);
	if (next) timerclear(next);

	loop->tid = pthread_self();

	struct timer *pos, *n;

	pthread_mutex_lock(&loop->timers_added_lock);
	list_for_each_entry_safe(pos, n, &loop->timers_added, node) {
		list_del(&pos->node);
		INIT_LIST_HEAD(&pos->node);
		list_add(&pos->node, &loop->timers);
	}
	pthread_mutex_unlock(&loop->timers_added_lock);

	pthread_mutex_lock(&loop->timers_lock);
	list_for_each_entry_safe(pos, n, &loop->timers, node) {
		if (!timerisset(&pos->timeout)) continue;

		if (timercmp(&pos->timeout, &now, >)) {
			if (next) {
				struct timeval __next;
				timersub(&pos->timeout, &now, &__next);
				if (timercmp(&__next, next, <) ||
				    !timerisset(next))
					*next = __next;
			}
			continue;
		}

		// calculate new timeout & next
		if (!timerisset(&pos->repeat)) {
			pos->timeout.tv_sec = 0;
			pos->timeout.tv_usec = 0;
		} else {
			do {
				timeradd(&pos->timeout, &pos->repeat,
				         &pos->timeout);
			} while (timercmp(&pos->timeout, &now, <));

			if (next) {
				struct timeval __next;
				timersub(&pos->timeout, &now, &__next);
				if (timercmp(&__next, next, <) ||
				    !timerisset(next))
					*next = __next;
			}
		}

		// call handler
		pos->handler(pos);

		/*
		 * do nothing after call handler as current timer
		 * will be killed in handler
		 */
	}
	pthread_mutex_unlock(&loop->timers_lock);

	return 0;
}
