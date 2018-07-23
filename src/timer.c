#include "timer.h"

#ifdef WIN32
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
	timer->killed = 0;
	INIT_LIST_HEAD(&timer->node);

	pthread_mutex_lock(&timers_lock);
	list_add(&timer->node, &timers);
	pthread_mutex_unlock(&timers_lock);
}

void kill_timer(struct timer *timer)
{
	timer->killed = 1;
}

void trigger_timer(struct timer *timer)
{
	gettimeofday(&timer->timeout, NULL);
}

int timers_init()
{
	pthread_mutex_init(&timers_lock, NULL);
	return 0;
}

int timers_close()
{
	pthread_mutex_destroy(&timers_lock);
	return 0;
}

int timers_run(struct timeval *next)
{
	pthread_t tid = pthread_self();
	struct timeval now;
	gettimeofday(&now, NULL);
	if (next) timerclear(next);

	pthread_mutex_lock(&timers_lock);
	struct timer *pos, *n;
	list_for_each_entry_safe(pos, n, &timers, node) {
		if (pos->tid != tid)
			continue;

		if (pos->killed) {
			list_del(&pos->node);
			continue;
		}

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

		// call handler
		pos->handler(pos);

		// delete killed timer after call handler
		if (pos->killed || !timerisset(&pos->repeat)) {
			list_del(&pos->node);
			continue;
		}

		// calculate new timeout & next
		do {
			timeradd(&pos->timeout, &pos->repeat, &pos->timeout);
		} while (timercmp(&pos->timeout, &now, <));

		if (next) {
			struct timeval __next;
			timersub(&pos->timeout, &now, &__next);
			if (timercmp(&__next, next, <) || !timerisset(next))
				*next = __next;
		}
	}
	pthread_mutex_unlock(&timers_lock);

	return 0;
}
