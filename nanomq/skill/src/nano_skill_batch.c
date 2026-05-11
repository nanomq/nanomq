// SPDX-License-Identifier: MIT

#include "nano_skill.h"

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
	void    *data;
	uint32_t size;
} batch_item;

struct nano_skill_batch {
	nano_skill_batch_flush_fn on_flush;
	void                     *cb_ctx;

	uint32_t max_count;
	uint32_t max_total_bytes;
	uint32_t flush_ms;

	pthread_t       th;
	pthread_mutex_t mtx;
	pthread_cond_t  cv;

	batch_item *items;
	uint32_t    count;
	uint32_t    cap;
	uint64_t    total_bytes;
	uint64_t    first_push_ms;

	bool stop;
	bool explicit_flush_pending;
};

static int
ensure_capacity(nano_skill_batch *b)
{
	if (b->count < b->cap) {
		return 0;
	}
	uint32_t new_cap = (b->cap == 0) ? 16 : b->cap * 2;
	batch_item *ni = (batch_item *) realloc(b->items, sizeof(batch_item) * new_cap);
	if (ni == NULL) {
		return -ENOMEM;
	}
	// zero new tail
	if (new_cap > b->cap) {
		memset(ni + b->cap, 0, sizeof(batch_item) * (new_cap - b->cap));
	}
	b->items = ni;
	b->cap   = new_cap;
	return 0;
}

static void
free_items(batch_item *items, uint32_t n)
{
	if (items == NULL) return;
	for (uint32_t i = 0; i < n; i++) {
		free(items[i].data);
		items[i].data = NULL;
		items[i].size = 0;
	}
}

static void
flush_locked(nano_skill_batch *b)
{
	if (b->count == 0) {
		b->explicit_flush_pending = false;
		return;
	}
	uint32_t n = b->count;

	void    **ptrs  = (void **) malloc(sizeof(void *) * n);
	uint32_t *sizes = (uint32_t *) malloc(sizeof(uint32_t) * n);
	if (ptrs == NULL || sizes == NULL) {
		free(ptrs);
		free(sizes);
		// Fallback: drop this batch to avoid deadlock on OOM.
		free_items(b->items, b->count);
		b->count                  = 0;
		b->total_bytes            = 0;
		b->first_push_ms          = 0;
		b->explicit_flush_pending = false;
		return;
	}

	for (uint32_t i = 0; i < n; i++) {
		ptrs[i]  = b->items[i].data;
		sizes[i] = b->items[i].size;
		b->items[i].data = NULL;
		b->items[i].size = 0;
	}

	b->count                  = 0;
	b->total_bytes            = 0;
	b->first_push_ms          = 0;
	b->explicit_flush_pending = false;

	nano_skill_batch_flush_fn cb = b->on_flush;
	void *cb_ctx = b->cb_ctx;

	pthread_mutex_unlock(&b->mtx);
	cb(ptrs, sizes, n, cb_ctx);
	for (uint32_t i = 0; i < n; i++) {
		free(ptrs[i]);
	}
	free(ptrs);
	free(sizes);
	pthread_mutex_lock(&b->mtx);
}

static void *
worker_main(void *arg)
{
	nano_skill_batch *b = (nano_skill_batch *) arg;

	pthread_mutex_lock(&b->mtx);
	while (!b->stop) {
		if (b->count == 0 && !b->explicit_flush_pending) {
			pthread_cond_wait(&b->cv, &b->mtx);
			continue;
		}
		if (b->explicit_flush_pending) {
			flush_locked(b);
			continue;
		}
		if (b->flush_ms == 0) {
			pthread_cond_wait(&b->cv, &b->mtx);
			continue;
		}

		uint64_t now = nano_skill_time_ms();
		uint64_t deadline = b->first_push_ms + (uint64_t) b->flush_ms;
		if (now >= deadline) {
			flush_locked(b);
			continue;
		}

		// timed wait
		struct timespec ts;
		clock_gettime(CLOCK_REALTIME, &ts);
		uint64_t wait_ms = deadline - now;
		uint64_t nsec = (uint64_t) ts.tv_nsec + (wait_ms % 1000ULL) * 1000000ULL;
		ts.tv_sec += (time_t) (wait_ms / 1000ULL) + (time_t) (nsec / 1000000000ULL);
		ts.tv_nsec = (long) (nsec % 1000000000ULL);
		(void) pthread_cond_timedwait(&b->cv, &b->mtx, &ts);
	}
	flush_locked(b);
	pthread_mutex_unlock(&b->mtx);
	return NULL;
}

nano_skill_batch *
nano_skill_batch_open(uint32_t max_count, uint32_t max_total_bytes, uint32_t flush_ms,
    nano_skill_batch_flush_fn on_flush, void *ctx)
{
	if (on_flush == NULL) return NULL;
	if (max_count == 0 && max_total_bytes == 0 && flush_ms == 0) return NULL;

	nano_skill_batch *b = (nano_skill_batch *) calloc(1, sizeof(*b));
	if (b == NULL) return NULL;

	b->on_flush        = on_flush;
	b->cb_ctx          = ctx;
	b->max_count       = max_count;
	b->max_total_bytes = max_total_bytes;
	b->flush_ms        = flush_ms;

	pthread_mutex_init(&b->mtx, NULL);
	pthread_cond_init(&b->cv, NULL);

	if (pthread_create(&b->th, NULL, worker_main, b) != 0) {
		pthread_cond_destroy(&b->cv);
		pthread_mutex_destroy(&b->mtx);
		free(b);
		return NULL;
	}
	return b;
}

int
nano_skill_batch_push(nano_skill_batch *b, const void *data, uint32_t len)
{
	if (b == NULL || (data == NULL && len > 0) || len == 0) return -EINVAL;

	void *copy = malloc(len);
	if (copy == NULL) return -ENOMEM;
	memcpy(copy, data, len);

	pthread_mutex_lock(&b->mtx);
	if (b->stop) {
		pthread_mutex_unlock(&b->mtx);
		free(copy);
		return -ESHUTDOWN;
	}
	if (ensure_capacity(b) != 0) {
		pthread_mutex_unlock(&b->mtx);
		free(copy);
		return -ENOMEM;
	}

	b->items[b->count].data = copy;
	b->items[b->count].size = len;
	b->count++;
	b->total_bytes += len;
	if (b->count == 1) {
		b->first_push_ms = nano_skill_time_ms();
	}

	bool trig_count = (b->max_count > 0 && b->count >= b->max_count);
	bool trig_bytes = (b->max_total_bytes > 0 && b->total_bytes >= b->max_total_bytes);
	if (trig_count || trig_bytes || b->count == 1) {
		pthread_cond_signal(&b->cv);
	}
	pthread_mutex_unlock(&b->mtx);
	return 0;
}

int
nano_skill_batch_flush(nano_skill_batch *b)
{
	if (b == NULL) return -EINVAL;
	pthread_mutex_lock(&b->mtx);
	b->explicit_flush_pending = true;
	pthread_cond_signal(&b->cv);
	pthread_mutex_unlock(&b->mtx);
	return 0;
}

void
nano_skill_batch_close(nano_skill_batch *b)
{
	if (b == NULL) return;

	pthread_mutex_lock(&b->mtx);
	b->stop = true;
	pthread_cond_signal(&b->cv);
	pthread_mutex_unlock(&b->mtx);

	(void) pthread_join(b->th, NULL);

	free_items(b->items, b->count);
	free(b->items);
	pthread_cond_destroy(&b->cv);
	pthread_mutex_destroy(&b->mtx);
	free(b);
}

