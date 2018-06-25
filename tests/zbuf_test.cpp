#include <assert.h>
#include <gtest/gtest.h>
#include "zbuf.h"

TEST(zbuf, basic)
{
	zbuf_t buf;

	char msg_hello[] = "hello";
	zbuf_init_data(&buf, msg_hello, sizeof(msg_hello));
	assert(zbuf_size(&buf) == sizeof(msg_hello));
	assert(strcmp((char *)zbuf_data(&buf), msg_hello) == 0);

	char msg_bla[] = "bla bla bla";
	zbuf_assign_data(&buf, msg_bla, sizeof(msg_bla));
	assert(zbuf_size(&buf) == sizeof(msg_bla));
	assert(strcmp((char *)zbuf_data(&buf), msg_bla) == 0);

	zbuf_close(&buf);
}
