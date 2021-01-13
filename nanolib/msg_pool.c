#include <stdio.h>
#include <nng/nng.h>
#include "msg_pool.h"
#include "zmalloc.h"
#include "dbg.h"

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
		pool->mutex    = 0; // TODO
		pool->pool = (nng_msg **)zmalloc(pool->capacity * sizeof(nng_msg*));
		pool->pool_start = pool->pool;
	}

	if (pool->pool != NULL) {
		for (i=0; i<pool->capacity; i++) {
			rv = rv | nng_msg_alloc(&pool->pool[i], 0);
		}
	}

	*poolp = pool;
	return rv;
}

uint8_t nnl_msg_get(nnl_msg_pool * pool, nng_msg ** msgp)
{
	uint8_t   rv = 0;
	if (nnl_msg_pool_empty(pool)) {
		rv = 1;
	}
	*msgp = NULL;
	if (rv == 0) {
		*msgp = pool->pool[pool->fronter];
		pool->fronter = (pool->fronter+1)%pool->capacity;
		pool->used++;
	}
	return rv;
}

uint8_t nnl_msg_put(nnl_msg_pool * pool, nng_msg ** msgp)
{
	uint8_t rv = 0;
	if (*msgp == NULL) {
		log("NNL_ERROR!!! msg is empty.");
	}
	if (nnl_msg_pool_full(pool)) {
		rv = 1;
	}
	if (rv == 0) {
		pool->pool[pool->footer] = *msgp;
		*msgp = NULL;
		pool->footer = (pool->footer+1)%pool->capacity;
		pool->used--;
	}
	return rv;
}

uint32_t nnl_msg_pool_capacity(nnl_msg_pool * pool)
{
	return pool->capacity;
}

uint32_t nnl_msg_pool_used(nnl_msg_pool * pool)
{
	return (pool->fronter-pool->footer)%pool->capacity;
}

uint8_t nnl_msg_pool_resize(nnl_msg_pool * pool, uint32_t size)
{
	uint8_t  rv = 0;
	uint32_t start = 0, end = 0, i = 0;
	nng_msg ** newpool = NULL;

	if (size < pool->used) {
		rv = 1;
	}

	if (rv == 0) {
		newpool = (nng_msg **)zmalloc(size * sizeof(nng_msg*));
		for (i=0; i<size; i++) {
			newpool[i] = NULL;
		}
	}

	if (newpool != NULL) {
		for (i=0; i<size; i++) newpool[i] = NULL;
		end = pool->fronter;
		if (pool->fronter < pool->footer) {
			end = pool->fronter + pool->capacity;
		}
		start = pool->footer;
		end = start + (size < pool->capacity ? size : pool->capacity);
		// copy msgs using & remain
		for (i=start; i<end; i++) {
			newpool[i%size] = pool->pool[i%pool->capacity];
			log("copy [%d]", i);
		}
		// resize to a smaller list
		for (i=end; i<start+pool->capacity; i++) {
			nng_msg_free(pool->pool[i%pool->capacity]);
			log("free [%d]", i);
		}
		// resize to a larger list
		for (i=0; i<size; i++) {
			if (newpool[i] == NULL) {
				rv = rv | nng_msg_alloc(&pool->pool[i], 0);
				log("address [%x]", pool->pool[i]);
			}
		}
		zfree(pool->pool);
		pool->pool = newpool;
		pool->capacity = size;
		pool->fronter %= pool->capacity;
		pool->footer  %= pool->capacity;
	}
	return rv;
}

uint8_t nnl_msg_pool_empty(nnl_msg_pool * pool)
{
	return (uint8_t)(pool->used == pool->capacity);
}

uint8_t nnl_msg_pool_full(nnl_msg_pool * pool)
{
	return (uint8_t)(pool->used == 0);
}

void nnl_msg_pool_delete(nnl_msg_pool * pool)
{
	uint8_t  rv = 0;
	uint32_t i;
	for (i=0; i<pool->capacity; i++) {
		nng_msg_free(pool->pool[i]);
	}
	zfree(pool->pool);
	zfree(pool);
}


