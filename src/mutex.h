#ifndef __ZERO_MUTEX_H
#define __ZERO_MUTEX_H

#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef pthread_mutex_t mutex_t;

static inline int mutex_init(mutex_t *mutex)
{
	return pthread_mutex_init(mutex, NULL);
}

static inline int mutex_close(mutex_t *mutex)
{
	return pthread_mutex_destroy(mutex);
}

static inline int mutex_lock(mutex_t *mutex)
{
	return pthread_mutex_lock(mutex);
}

static inline int mutex_trylock(mutex_t *mutex)
{
	return pthread_mutex_trylock(mutex);
}

static inline int mutex_unlock(mutex_t *mutex)
{
	return pthread_mutex_unlock(mutex);
}

#ifdef __cplusplus
}
#endif
#endif
