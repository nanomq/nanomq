//
// Copyright 2020 NanoMQ Team, Inc. <jaylin@emqx.io> //
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef __NANO_ALLOC_H__
#define __NANO_ALLOC_H__

#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NANO_ARG_UNUSED(x) ((void) x)

void *nano_alloc(size_t sz);
void *nano_zalloc(size_t sz);
void  nano_free(void *b, size_t z);

#define NANO_ALLOC_STRUCT(s) nano_zalloc(sizeof(*s))
#define NANO_FREE_STRUCT(s) nano_free((s), sizeof(*s))
#define NANO_ALLOC_STRUCTS(s, n) nano_zalloc(sizeof(*s) * n)
#define NANO_FREE_STRUCTS(s, n) nano_free(s, sizeof(*s) * n)

#ifdef __cplusplus
}
#endif

#endif
