#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <pthread.h>
#include <unistd.h>
#include "timer.h"

static void second_do_sth(struct timer *timer, void *arg)
{
	static int count = 0;
	if (count == 3) {
		timer_stop(timer);
		*(int *)arg = 1;
	} else {
		count++;
		timer_start(timer, second_do_sth, arg, 500, 0);
	}
}

static void *second_timer_thread(void *arg)
{
	int exit_flag = 0;
	struct timer *timer = timer_new();
	timer_start(timer, second_do_sth, &exit_flag, 1000, 0);

	long next;
	while (exit_flag == 0) {
		timer_loop(&next);
		usleep(next * 1000);
	}

	timer_destroy(timer);
	return NULL;
}

static void do_sth(struct timer *timer, void *arg)
{
	static int count = 0;
	if (count == 1) {
		timer_stop(timer);
		*(int *)arg = 1;
	} else {
		count++;
		timer_start(timer, do_sth, arg, 500, 0);
	}
}

static void test_timer(void **status)
{
	pthread_t pid;
	pthread_create(&pid, NULL, second_timer_thread, NULL);

	int exit_flag = 0;
	struct timer *timer = timer_new();
	timer_start(timer, do_sth, &exit_flag, 1000, 0);

	long next;
	timer_loop(&next);
	assert_true(next <= 1000);
	assert_true(next > 990);
	assert_true(exit_flag == 0);
	usleep(next * 1000);
	timer_loop(&next);
	assert_true(exit_flag == 0);
	assert_true(next <= 1000); // not 500
	assert_true(next > 990); // not 490
	usleep(next * 1000);
	timer_loop(&next);
	assert_true(exit_flag == 1);
	assert_true(next <= 1000);
	assert_true(next > 990);

	timer_destroy(timer);

	pthread_join(pid, NULL);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_timer),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
