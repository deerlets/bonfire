#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#ifdef __linux__
#include <sys/random.h>
#endif
#include "stdlibx.h"

size_t random_gen(void *buf, size_t size)
{
#ifdef __linux__
	assert(getrandom(buf, size, GRND_NONBLOCK) == size);
#elif defined(__unix__) || defined(__APPLE__)
	int fd = open("/dev/urandom", O_RDONLY);
	assert(fd != -1);
	assert(read(fd, buf, size) == size);
	close(fd);
#else
	static int entropy = 314;
	if (entropy == 314)
		srand(time(NULL) * entropy++);
	for (size_t i = 0; i < size; i++)
		((char *)buf)[i] = rand() % 0x100;
#endif
	return size;
}

char *uuid_v4_gen()
{
	char *retval;

	union {
		struct {
			uint32_t time_low;
			uint16_t time_mid;
			uint16_t time_hi_and_version;
			uint8_t  clk_seq_hi_res;
			uint8_t  clk_seq_low;
			uint8_t  node[6];
		};
		uint8_t __rnd[16];
	} uuid;

	random_gen(uuid.__rnd, 16);

	// Refer Section 4.2 of RFC-4122
	// https://tools.ietf.org/html/rfc4122#section-4.2
	uuid.clk_seq_hi_res = (uint8_t)((uuid.clk_seq_hi_res & 0x3F) | 0x80);
	uuid.time_hi_and_version =
		(uint16_t)((uuid.time_hi_and_version & 0x0FFF) | 0x4000);

	retval = malloc(37);
	snprintf(retval, 37, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
	         uuid.time_low, uuid.time_mid, uuid.time_hi_and_version,
	         uuid.clk_seq_hi_res, uuid.clk_seq_low,
	         uuid.node[0], uuid.node[1], uuid.node[2],
	         uuid.node[3], uuid.node[4], uuid.node[5]);

	return retval;
}
