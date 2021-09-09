//
// Copyright 2020 NanoMQ Team, Inc. <jaylin@emqx.io> //
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef NANO_LMQ_H
#define NANO_LMQ_H

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

// nano_lmq is a very lightweight message queue.  Defining it this way allows
// us to share some common code.  Locking must be supplied by the caller.
// For performance reasons, this is allocated inline.
typedef struct nano_lmq {
	size_t lmq_cap;
	size_t lmq_alloc; // alloc is cap, rounded up to power of 2
	size_t lmq_mask;
	size_t lmq_len;
	size_t lmq_get;
	size_t lmq_put;
	void **lmq_msgs;
} nano_lmq;

typedef void (*nano_lmq_free)(void *content);
typedef void *(*nano_lmq_get_sub_msg)(void *msg);

extern int  nano_lmq_init(nano_lmq *lmq, size_t cap);
extern void nano_lmq_fini(nano_lmq *);
extern void nano_lmq_fini_with_cb(
    nano_lmq *, nano_lmq_free, nano_lmq_get_sub_msg);
extern void nano_lmq_flush(nano_lmq *);
extern void nano_lmq_flush_with_cb(
    nano_lmq *, nano_lmq_free, nano_lmq_get_sub_msg);
extern size_t nano_lmq_len(nano_lmq *);
extern size_t nano_lmq_cap(nano_lmq *);
extern int    nano_lmq_putq(nano_lmq *, void *);
extern int    nano_lmq_getq(nano_lmq *, void **);
extern int    nano_lmq_resize(nano_lmq *, size_t);
extern int    nano_lmq_resize_with_cb(nano_lmq *lmq, size_t cap,
       nano_lmq_free free_cb, nano_lmq_get_sub_msg get_sub_msg);
extern bool   nano_lmq_full(nano_lmq *);
extern bool   nano_lmq_empty(nano_lmq *);

#endif // NANO_LMQ_H
