#include "timer.h"

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

static LIST_HEAD(timers);
static pthread_mutex_t timers_lock;

static LIST_HEAD(timers_added);
static pthread_mutex_t timers_added_lock;

void set_timer(struct timer *timer, timer_handler_func_t handler,
               void *arg, uint64_t timeout, uint64_t repeat)
{
	timer->handler = handler;
	timer->arg = arg;
	timer->timeout.tv_sec = time(NULL) + timeout / 1000;
	timer->timeout.tv_usec = timeout % 1000 * 1000;
	timer->repeat.tv_sec = repeat / 1000;
	timer->repeat.tv_usec = repeat % 1000 * 1000;
	timer->tid = pthread_self();
	INIT_LIST_HEAD(&timer->node);

	pthread_mutex_lock(&timers_added_lock);
	list_add(&timer->node, &timers_added);
	pthread_mutex_unlock(&timers_added_lock);
}

void kill_timer(struct timer *timer)
{
	if (timer->tid == pthread_self()) {
		list_del(&timer->node);
	} else {
		pthread_mutex_lock(&timers_lock);
		list_del(&timer->node);
		pthread_mutex_unlock(&timers_lock);
	}
}

void trigger_timer(struct timer *timer)
{
	if (timer->tid == pthread_self()) {
		gettimeofday(&timer->timeout, NULL);
	} else {
		pthread_mutex_lock(&timers_lock);
		gettimeofday(&timer->timeout, NULL);
		pthread_mutex_unlock(&timers_lock);
	}
}

int timers_init()
{
	pthread_mutex_init(&timers_lock, NULL);
	pthread_mutex_init(&timers_added_lock, NULL);
	return 0;
}

int timers_close()
{
	pthread_mutex_destroy(&timers_lock);
	pthread_mutex_destroy(&timers_added_lock);
	return 0;
}

int timers_run(struct timeval *next)
{
	pthread_t tid = pthread_self();
	struct timeval now;
	gettimeofday(&now, NULL);
	if (next) timerclear(next);

	struct timer *pos, *n;

	pthread_mutex_lock(&timers_added_lock);
	list_for_each_entry_safe(pos, n, &timers_added, node) {
		list_del(&pos->node);
		INIT_LIST_HEAD(&pos->node);
		list_add(&pos->node, &timers);
	}
	pthread_mutex_unlock(&timers_added_lock);

	pthread_mutex_lock(&timers_lock);
	list_for_each_entry_safe(pos, n, &timers, node) {
		if (pos->tid != tid)
			continue;

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
		if (timerisset(&pos->repeat)) {
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
	pthread_mutex_unlock(&timers_lock);

	return 0;
}
