#include <stdio.h>
#include <time.h>
#include <nng/nng.h>
#include <nng/supplemental/util/platform.h>

#include "msg_pool.h"
#include "zmalloc.h"
#include "dbg.h"

static nng_mtx * msg_mutex;     // mutex when msg get/put
static nng_mtx * pool_mutex;    // mutex when resize
static nng_cv  * pool_cv;       // cv when resize
static nng_mtx * pool_cv_mutex; // cv alloc needed
static nng_aio * aio_resize;
static uint32_t  target_sz = 0;

uint8_t nnl_msg_pool_create(nnl_msg_pool ** poolp)
{
	uint8_t  rv = 0;
	uint32_t i = 0;
	nnl_msg_pool * pool = (nnl_msg_pool *)zmalloc(sizeof(nnl_msg_pool));
	if (pool != NULL) {
		pool->capacity = NANOLIB_MSG_POOL_SIZE;
		pool->used     = 0;
		pool->fronter  = 0;
		pool->footer   = 0;
		pool->pool = (nng_msg **)zmalloc(pool->capacity * sizeof(nng_msg*));
		pool->pool_start = pool->pool;
	}

	if (pool->pool != NULL && rv == 0) {
		for (i=0; i<pool->capacity; i++) {
			rv = rv | nng_msg_alloc(&pool->pool[i], NNL_MSG_SIZE_DEFAULT);
		}
	}

	if (rv == 0) {
		rv |= (uint8_t)nng_mtx_alloc(&msg_mutex);
		rv |= (uint8_t)nng_mtx_alloc(&pool_mutex);
		rv |= (uint8_t)nng_mtx_alloc(&pool_cv_mutex);
		rv |= (uint8_t)nng_cv_alloc(&pool_cv, pool_cv_mutex);
		rv |= (int)nng_aio_alloc(&aio_resize, nnl_msg_pool_resize, pool);
	}

	if (rv != 0) {
		log_err("NNL_ERROR: error in msg pool create");
		nnl_msg_pool_delete(pool);
	}
	*poolp = pool;
	return rv;
}

uint8_t nnl_msg_pool_get(nnl_msg_pool * pool, nng_msg ** msgp)
{
	uint8_t rv = 0;
	*msgp = pool->pool[pool->fronter];
	nng_msg_clear(*msgp);
	nng_msg_header_clear(*msgp);
	nng_msg_set_refcnt(*msgp, 1);
	pool->fronter = (pool->fronter+1)%pool->capacity;
	pool->used++;
	return rv;
}

uint8_t nnl_msg_pool_put(nnl_msg_pool * pool, nng_msg * msg)
{
	uint8_t rv = 0;
	pool->pool[pool->footer] = msg;
	pool->footer = (pool->footer+1)%pool->capacity;
	pool->used--;
	return rv;
}

uint8_t nnl_msg_get(nnl_msg_pool * pool, nng_msg ** msgp)
{
	uint8_t rv = 0;
	if (nnl_msg_pool_used(pool)/nnl_msg_pool_capacity(pool) > 2/3) {
		nng_mtx_lock(msg_mutex);
		if (target_sz <= pool->capacity) {
			target_sz = 2 * pool->capacity;
			nng_aio_finish_sync(aio_resize, 0);
		}
		// rv |= nnl_msg_pool_resize(pool, 2 * pool->capacity);
		nng_mtx_unlock(msg_mutex);
	}

	nng_mtx_lock(pool_cv_mutex);
	if (pool->used >= pool->capacity) {
		nng_cv_wait(pool_cv);
	}
	nng_mtx_unlock(pool_cv_mutex);

	if (rv == 0) {
		nng_mtx_lock(msg_mutex);
		rv |= nnl_msg_pool_get(pool, msgp);
		nng_mtx_unlock(msg_mutex);
	}
	log_info("MSG GETTED AND USED NOW IS (%d)", pool->used);
#ifdef DEBUG
	if (rv == 1) {
		log_err("ERROR: error in msg get!!");
	}
#endif
	return rv;
}

uint8_t nnl_msg_put(nnl_msg_pool * pool, nng_msg ** msgp)
{
	uint8_t  rv  = 0;
	nng_msg *msg = *msgp;

	if (!pool) return 1;
	if (msg == NULL) {
		debug("NNL_ERROR: msg is empty.");
#if DEBUG
		nng_msg_refcnt(msg); // for backtrace
#endif
		rv = 1;
	}
	if (nnl_msg_pool_full(pool)) {
		rv = 1;
	}
	if (rv == 0) {
		nng_mtx_lock(msg_mutex);
		if (nng_msg_refcnt(msg) < 1) {
			debug("NNL_ERROR: ------error of refcnt 0!!!!!!!!!!");
			log_err("NNL_ERROR: ------error of refcnt 0!!!!!!!!!!");
			nng_msg_set_refcnt(msg, 1);
			nng_msg_clear(msg);
			nng_msg_header_clear(msg);
			*msgp = NULL;
		} else if (nng_msg_refcnt(msg) > 1) {
			nng_msg_free(msg);
		} else {
			rv = nnl_msg_pool_put(pool, msg);
			*msgp = NULL;
		}
		nng_mtx_unlock(msg_mutex);
	}
	log_info("MSG PUTTED AND USED NOW IS (%d)", pool->used);
	return rv;
}

uint8_t nnl_msg_pool_resize(nnl_msg_pool * pool)
{
	uint8_t  rv = 0;
	uint32_t start = 0, end = 0, i = 0, size = target_sz;
	nng_msg ** newpool = NULL;

	if (size < pool->used || size < NANOLIB_MSG_POOL_SIZE) {
		return 1;
	}

	nng_mtx_lock(pool_mutex);

	if (nnl_msg_pool_used(pool)/nnl_msg_pool_capacity(pool) < 2/3) {
		nng_mutex_unlock(pool_mutex);
		return rv;
	}
	log_info("resize to [%d]\n", size);
	debug("resize !!!!!!!!! to [%d]\n", size);

	if (rv == 0) {
		newpool = (nng_msg **)zmalloc(size * sizeof(nng_msg*));
		for (i=0; i<size; i++) {
			newpool[i] = NULL;
		}
	}

	if (newpool != NULL) {
		start = pool->footer;
		end = start + (size < pool->capacity ? size : pool->capacity);
		// copy msgs using & remain
		for (i=start; i<end; i++) {
			log_info("copy [%d] -> [%d] [%p]", i%pool->capacity, i-start, pool->pool[i%pool->capacity]);
			newpool[i-start] = pool->pool[i%pool->capacity];
		}
		// resize to a smaller list
		for (i=end; i<start+pool->capacity; i++) {
			log_info("free [%d] [%p]", i%pool->capacity, pool->pool[i%pool->capacity]);
			while (nng_msg_refcnt(pool->pool[i%pool->capacity]) > 0) {
				nng_msg_free(pool->pool[i%pool->capacity]);
			}
		}
		// resize to a larger list
		for (i=0; i<size; i++) {
			if (newpool[i] == NULL) {
				rv = rv | nng_msg_alloc(&newpool[i], NNL_MSG_SIZE_DEFAULT);
				log_info("alloc [%d] [%p]", i%size, newpool[i]);
			}
		}
		zfree(pool->pool);
		pool->pool = newpool;
		pool->capacity = size;
		pool->fronter  = pool->used;
		pool->footer   = 0;
	}
	nng_mtx_unlock(pool_mutex);

	nng_mtx_lock(pool_cv_mutex);
	nng_cv_wake(pool_cv);
	nng_mtx_unlock(pool_cv_mutex);
	return rv;
}

uint8_t nnl_msg_pool_empty(nnl_msg_pool * pool)
{
	if (pool == NULL) {
		log_err("NNL_ERROR: error due to pool is empty");
		return 1;
	}
	return (uint8_t)(pool->used == pool->capacity);
}

uint8_t nnl_msg_pool_full(nnl_msg_pool * pool)
{
	if (pool == NULL) {
		log_err("NNL_ERROR: error due to pool is empty");
		return 1;
	}
	return (uint8_t)(pool->used == 0);
}

void nnl_msg_pool_delete(nnl_msg_pool * pool)
{
	uint8_t  rv = 0;
	uint32_t i;
	if (pool && pool->pool) {
		for (i=0; i<pool->capacity; i++) {
			while (nng_msg_refcnt(pool->pool[i]) > 1) {
				nng_msg_free(pool->pool[i]);
			}
			nng_msg_free(pool->pool[i]);
		}
	}
	zfree(pool->pool);
	zfree(pool);
	nng_mtx_free(msg_mutex);
	nng_mtx_free(pool_mutex);
	nng_mtx_free(pool_cv_mutex);
	nng_cv_free(pool_cv);
	nng_aio_free(aio_resize);
}

uint32_t nnl_msg_pool_capacity(nnl_msg_pool * pool)
{
	if (!pool) return NANOLIB_MSG_POOL_SIZE;
	return pool->capacity;
}

uint32_t nnl_msg_pool_used(nnl_msg_pool * pool)
{
	if (!pool) return 0;
	return pool->used;
}

uint8_t nnl_msg_put_force(nnl_msg_pool * pool, nng_msg ** msgp)
{
	uint8_t  rv  = 0;
	nng_msg *msg = *msgp;

	if (msg == NULL) {
		log_err("NNL_ERROR!!! msg is empty.");
		rv = 1;
	}
	if (nnl_msg_pool_full(pool)) {
		rv = 1;
	}
	if (rv == 0) {
		nng_mtx_lock(msg_mutex);
		nng_msg_set_refcnt(msg, 1);
		rv = nnl_msg_pool_put(pool, msg);
		*msgp = NULL;
		nng_mtx_unlock(msg_mutex);
	}
	log_info("--FORCE--MSG PUTTED AND USED NOW IS (%d)", pool->used);
	return rv;
}

uint64_t nnl_now()
{
	uint64_t msec;
	struct timespec ts;
	if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
		log("ERROR in get time");
	}
	msec = ts.tv_sec;
	msec *= 1000;
	msec += (ts.tv_nsec / 1000000);
	return (msec);
}

