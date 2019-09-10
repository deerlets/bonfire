#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include "module.h"

static void test_module(void **status)
{
	int rc, value;
	char buf[256];
	struct module *mod;

	mod = load_module("./test", NULL);
	assert_true(mod == NULL);
	assert_true(mod_errno() == MOD_EOPEN);

#if defined(__CYGWIN__) || defined(__MINGW32__)
	mod = load_module("mock_module.zo", "myint=1");
#else
	mod = load_module("../lib/mock_module.zo", "myint=1");
#endif
	assert_true(mod);
	param_get_int("myint", &value, mod->param);
	assert_true(value == 1);
	unload_module(mod);

#if defined(__CYGWIN__) || defined(__MINGW32__)
	mod = load_module("mock_module.zo",
	                  "myint=1 mystr=\"hello world\"");
#else
	mod = load_module("../lib/mock_module.zo",
	                  "myint=1 mystr=\"hello world\"");
#endif
	assert_true(mod);
	param_get_int("myint", &value, mod->param);
	assert_true(value == 1);
	param_get_string("mystr", buf, sizeof(buf), mod->param);
	assert_string_equal(buf, "hello world");
	module_set_info(mod, "alias for mock_module", "I'm a mock module");
	unload_module(mod);

	rc = load_modules_from_dir("./test_dir");
	assert_true(rc == -1);
	assert_true(mod_errno() == MOD_EOPEN);

	rc = unload_all_modules();
	assert_true(rc == 0);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_module),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
