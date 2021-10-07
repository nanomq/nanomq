//
// Copyright 2021 NanoMQ Team, Inc. <jaylin@emqx.io> //
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "nano_lmq.h"
#include "nano_alloc.h"

// Light-weight message queue. These are derived from our heavy-weight
// message queues, but are less "featureful", but more useful for
// performance sensitive contexts.  Locking must be done by the caller.

int
nano_lmq_init(nano_lmq *lmq, size_t cap)
{
	size_t alloc;

	// We prefer alloc to a power of 2, this allows us to do modulo
	// operations as a power of two, for efficiency.  It does possibly
	// waste some space, but never more than 2x.  Consumers should try
	// for powers of two if they are concerned about efficiency.
	alloc = 2;
	while (alloc < cap) {
		alloc *= 2;
	}
	if ((lmq->lmq_msgs = nano_alloc(sizeof(void *) * alloc)) == NULL) {
		NANO_FREE_STRUCT(lmq);
		return (-2);
	}
	lmq->lmq_cap   = cap;
	lmq->lmq_alloc = alloc;
	lmq->lmq_mask  = (alloc - 1);
	lmq->lmq_len   = 0;
	lmq->lmq_get   = 0;
	lmq->lmq_put   = 0;

	return (0);
}

void
nano_lmq_fini(nano_lmq *lmq)
{
	if (lmq == NULL) {
		return;
	}

	/* Free any orphaned messages. */
	while (lmq->lmq_len > 0) {
		void *msg = lmq->lmq_msgs[lmq->lmq_get++];
		lmq->lmq_get &= lmq->lmq_mask;
		lmq->lmq_len--;
		NANO_FREE_STRUCT(msg);
	}

	nano_free(lmq->lmq_msgs, lmq->lmq_alloc * sizeof(void *));
}

void
nano_lmq_fini_with_cb(
    nano_lmq *lmq, nano_lmq_free free_cb, nano_lmq_get_sub_msg get_sub_cb)
{
	if (lmq == NULL) {
		return;
	}

	/* Free any orphaned messages. */
	while (lmq->lmq_len > 0) {
		void *msg = lmq->lmq_msgs[lmq->lmq_get++];
		lmq->lmq_get &= lmq->lmq_mask;
		lmq->lmq_len--;
		void *sub_msg = get_sub_cb(msg);
		if (sub_msg) {
			free_cb(sub_msg);
		}
		NANO_FREE_STRUCT(msg);
	}

	nano_free(lmq->lmq_msgs, lmq->lmq_alloc * sizeof(void *));
}

void
nano_lmq_flush(nano_lmq *lmq)
{
	while (lmq->lmq_len > 0) {
		void *msg = lmq->lmq_msgs[lmq->lmq_get++];
		lmq->lmq_get &= lmq->lmq_mask;
		lmq->lmq_len--;
		NANO_FREE_STRUCT(msg);
	}
}

void
nano_lmq_flush_with_cb(
    nano_lmq *lmq, nano_lmq_free free_cb, nano_lmq_get_sub_msg get_sub_cb)
{
	while (lmq->lmq_len > 0) {
		void *msg = lmq->lmq_msgs[lmq->lmq_get++];
		lmq->lmq_get &= lmq->lmq_mask;
		lmq->lmq_len--;
		void *sub_msg = get_sub_cb(msg);
		if (sub_msg) {
			free_cb(sub_msg);
		}
		NANO_FREE_STRUCT(msg);
	}
}

size_t
nano_lmq_len(nano_lmq *lmq)
{
	return (lmq->lmq_len);
}

size_t
nano_lmq_cap(nano_lmq *lmq)
{
	return (lmq->lmq_cap);
}

bool
nano_lmq_full(nano_lmq *lmq)
{
	return (lmq->lmq_len >= lmq->lmq_cap);
}

bool
nano_lmq_empty(nano_lmq *lmq)
{
	return (lmq->lmq_len == 0);
}

int
nano_lmq_putq(nano_lmq *lmq, void *msg)
{
	if (lmq->lmq_len >= lmq->lmq_cap) {
		return (-8);
	}
	lmq->lmq_msgs[lmq->lmq_put++] = msg;
	lmq->lmq_len++;
	lmq->lmq_put &= lmq->lmq_mask;
	return (0);
}

int
nano_lmq_getq(nano_lmq *lmq, void **msgp)
{
	void *msg;
	if (lmq->lmq_len == 0) {
		return (-8);
	}
	msg = lmq->lmq_msgs[lmq->lmq_get++];
	lmq->lmq_get &= lmq->lmq_mask;
	lmq->lmq_len--;
	*msgp = msg;
	return (0);
}

int
nano_lmq_resize(nano_lmq *lmq, size_t cap)
{
	void * msg;
	void **newq;
	size_t alloc;
	size_t len;

	alloc = 2;
	while (alloc < cap) {
		alloc *= 2;
	}

	newq = nano_alloc(sizeof(void *) * alloc);
	if (newq == NULL) {
		return (-2);
	}

	len = 0;
	while ((len < cap) && (nano_lmq_getq(lmq, &msg) == 0)) {
		newq[len++] = msg;
	}

	// Flush anything left over.
	nano_lmq_flush(lmq);

	nano_free(lmq->lmq_msgs, lmq->lmq_alloc * sizeof(void *));
	lmq->lmq_msgs  = newq;
	lmq->lmq_cap   = cap;
	lmq->lmq_alloc = alloc;
	lmq->lmq_mask  = alloc - 1;
	lmq->lmq_len   = len;
	lmq->lmq_put   = len;
	lmq->lmq_get   = 0;

	return (0);
}

int
nano_lmq_resize_with_cb(nano_lmq *lmq, size_t cap, nano_lmq_free free_cb,
    nano_lmq_get_sub_msg get_sub_msg)
{
	void * msg;
	void **newq;
	size_t alloc;
	size_t len;

	alloc = 2;
	while (alloc < cap) {
		alloc *= 2;
	}

	newq = nano_alloc(sizeof(void *) * alloc);
	if (newq == NULL) {
		return (-2);
	}

	len = 0;
	while ((len < cap) && (nano_lmq_getq(lmq, &msg) == 0)) {
		newq[len++] = msg;
	}

	// Flush anything left over.
	nano_lmq_flush_with_cb(lmq, free_cb, get_sub_msg);

	nano_free(lmq->lmq_msgs, lmq->lmq_alloc * sizeof(void *));
	lmq->lmq_msgs  = newq;
	lmq->lmq_cap   = cap;
	lmq->lmq_alloc = alloc;
	lmq->lmq_mask  = alloc - 1;
	lmq->lmq_len   = len;
	lmq->lmq_put   = len;
	lmq->lmq_get   = 0;

	return (0);
}