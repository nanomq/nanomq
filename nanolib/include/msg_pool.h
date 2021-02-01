#ifndef NANOLIB_MSG_POOL
#define NANOLIB_MSG_POOL

#include <stdio.h>
#include <stdint.h>
#include <nng/nng.h>

#ifndef NNL_MSG_SIZE_DEFAULT
#define NNL_MSG_SIZE_DEFAULT 360
#endif

#ifndef NANOLIB_MSG_POOL_SIZE
#define NANOLIB_MSG_POOL_SIZE 512
#endif

struct nnl_msg_pool {
	uint32_t    capacity;
	uint32_t    used;
	uint32_t    fronter;
	uint32_t    footer;
	nng_msg  ** pool_start;
	nng_msg  ** pool;
};
typedef struct nnl_msg_pool nnl_msg_pool;

uint8_t nnl_msg_pool_create(nnl_msg_pool **);
uint8_t nnl_msg_get(nnl_msg_pool *, nng_msg **);
uint8_t nnl_msg_put(nnl_msg_pool *, nng_msg **);
uint8_t nnl_msg_pool_get(nnl_msg_pool *, nng_msg **);
uint8_t nnl_msg_pool_put(nnl_msg_pool *, nng_msg *);
uint32_t nnl_msg_pool_capacity(nnl_msg_pool *);
uint32_t nnl_msg_pool_used(nnl_msg_pool *);
uint8_t nnl_msg_pool_resize(nnl_msg_pool *, uint32_t);
uint8_t nnl_msg_pool_empty(nnl_msg_pool *);
uint8_t nnl_msg_pool_full(nnl_msg_pool *);
void nnl_msg_pool_delete(nnl_msg_pool *);
uint8_t nnl_msg_put_force(nnl_msg_pool *, nng_msg **);

#endif
