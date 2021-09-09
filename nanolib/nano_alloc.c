//
// Copyright 2020 NanoMQ Team, Inc. <jaylin@emqx.io> //
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "nano_alloc.h"

void *
nano_alloc(size_t sz)
{
	return (sz > 0 ? malloc(sz) : NULL);
}

void *
nano_zalloc(size_t sz)
{
	return (sz > 0 ? calloc(1, sz) : NULL);
}

void
nano_free(void *b, size_t z)
{
	NANO_ARG_UNUSED(z);
	free(b);
}
