#include "module.h"

static int mock_module_init(void)
{
	return 0;
}

static void mock_module_exit(void)
{
}

module_init(mock_module_init)
module_exit(mock_module_exit)
