// SPDX-License-Identifier: MIT

#include "nano_skill.h"

#include <time.h>

uint64_t
nano_skill_time_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t) ts.tv_sec * 1000ULL + (uint64_t) ts.tv_nsec / 1000000ULL;
}

