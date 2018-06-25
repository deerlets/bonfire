#include <assert.h>
#include <gtest/gtest.h>
#include "module.h"

TEST(module, basic)
{
	int rc, value;
	char buf[256];
	struct module *mod;

	mod = load_module("./test", NULL);
	assert(mod == NULL);
	assert(mod_errno() == MOD_EOPEN);

	mod = load_module("mock_module.zo", "myint=1");
	assert(mod);
	param_get_int("myint", &value, mod->param);
	assert(value == 1);
	unload_module(mod);

	mod = load_module("mock_module.zo", "myint=1 mystr=\"hello world\"");
	assert(mod);
	param_get_int("myint", &value, mod->param);
	assert(value == 1);
	param_get_string("mystr", buf, sizeof(buf), mod->param);
	assert(strcmp(buf, "hello world") == 0);
	unload_module(mod);

	rc = load_modules_from_dir("./test_dir");
	assert(rc == -1);
	assert(mod_errno() == MOD_EOPEN);

	rc = unload_all_modules();
	assert(rc == 0);
}
