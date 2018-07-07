#include <gtest/gtest.h>
#include "utils.h"

TEST(utils, timeval)
{
	struct timeval tv;

	tv.tv_sec = 11;
	tv.tv_usec = 12345;
	ASSERT_EQ(11.012345, timeval_to_double(&tv));

	tv.tv_sec = 1111;
	tv.tv_usec = 123456;
	ASSERT_EQ(1111.123456, timeval_to_double(&tv));

	double_to_timeval(22.23451, &tv);
	ASSERT_EQ(tv.tv_sec, 22);
	ASSERT_EQ(tv.tv_usec, 234510);

	double_to_timeval(44.123456, &tv);
	ASSERT_EQ(tv.tv_sec, 44);
	ASSERT_GE(tv.tv_usec, 123450);
	ASSERT_LE(tv.tv_usec, 123460);
}
