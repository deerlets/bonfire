#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include "extlog.h"

static void test_log_level(void **status)
{
	assert_true(log_set_level(LOG_LV_WARN) == LOG_LV_INFO);
	assert_true(log_set_level(LOG_LV_FATAL) == LOG_LV_WARN);
	assert_true(log_set_level(LOG_LV_NONE) == LOG_LV_FATAL);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_log_level),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
