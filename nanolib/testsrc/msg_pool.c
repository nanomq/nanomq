#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>

#include "../include/msg_pool.h"
#include "../include/dbg.h"

#define NUM_THREADS 256
#define MSG_NUM_IN_THREAD 1000

typedef struct thread_args {
	int num;
	nng_msg * msgs[200];
}targs;

nnl_msg_pool * mp;

uint8_t test_one_get_one_put()
{
	uint8_t rv = 0;
	nng_msg * msg;
	rv |= nnl_msg_get(mp, &msg);
	rv |= nnl_msg_put(mp, &msg);
	return rv;
}

uint8_t test_multi_get(int n, nng_msg ** msgs)
{
	nng_msg * msg;
	uint8_t rv = 0;
	for(int i=0; i<n; i++){
		rv |= nnl_msg_get(mp, &msgs[i]);
		if(rv) log("rv: [%d] address [%p]", rv, msgs[i]);
	}
	return rv;
}

uint8_t test_multi_put(int n, nng_msg ** msgs)
{
	nng_msg * msg;
	uint8_t rv = 0;
	for(int i=0; i<n; i++){
		if (msgs[i]) {
			rv |= nnl_msg_put(mp, &msgs[i]);
		} else {
			rv = 1;
		}
		if(rv) log("rv: [%d] address [%p]", rv, msgs[i]);
	}
	return rv;
}

nng_msg * msgs[1000];

void * thread_test_multi_get(void * n)
{
	uint8_t rv = test_multi_get(*(int *)n, msgs);
	pthread_exit((void *)rv);
}

void * thread_test_multi_put(void * n)
{
	uint8_t rv = test_multi_put(*(int *)n, msgs);
	pthread_exit((void *)rv);
}

uint8_t test_one_concurrent()
{
	uint8_t   rv;
	pthread_t threads[2];
	void * status;
	int num[1] = {1000};

	rv |= pthread_create(&threads[0], NULL, thread_test_multi_get, (void *)&num[0]);
	rv |= pthread_create(&threads[1], NULL, thread_test_multi_put, (void *)&num[0]);

	if (!rv) {
		rv |= pthread_join(threads[0], &status);
		log("rv about T0 [%d]", rv);
		rv |= pthread_join(threads[1], &status);
		log("rv about T1 [%d]", rv);
	}

	return rv;
}

void * thread_test_one_get_one_put(void * t)
{
	uint8_t rv = 0;
	targs * ta = t;
	for (int i=0; i<ta->num; i++)
		rv += test_one_get_one_put();
	free(ta);
	pthread_exit((void *)&rv);
}

uint8_t test_two_concurrent()
{
	uint8_t   rv = 0;
	pthread_t threads[NUM_THREADS];
	void * status;
	int num = MSG_NUM_IN_THREAD;

	for (int i=0; i<NUM_THREADS; i++) {
		targs * t = malloc(sizeof(targs));
		rv |= pthread_create(&threads[i], NULL, thread_test_one_get_one_put, (void *)t);
		if (rv) {
			debug("ERROR in thread create");
			break;
		}
	}

	if (!rv) {
		for (int i=0; i<NUM_THREADS; i++) {
			rv |= pthread_join(threads[i], &status);
		}
		debug("rv about Tx [%d]", rv);
	}

	return rv;
}

char * test_msg_pool()
{
	uint8_t rv = 0;
	debug("create msg pool?");
	CHECK(nnl_msg_pool_create(&mp) == 0);
	CHECK(test_two_concurrent() == 0);
	debug("delete msg pool.");
	nnl_msg_pool_delete(mp);
	return NULL;
}

char * test_compare_malloc_msg_pool_get()
{
	uint8_t rv = 0;
	uint32_t num = 8190;
	uint64_t now;
	nng_msg * mq[num];
	CHECK(nnl_msg_pool_create(&mp) == 0);
	now = nnl_now();
	for(int i=0; i<num; i++) {
		nng_msg_alloc(&mq[i], 256);
	}
	debug("[%ld]", nnl_now()-now);
	for(int i=0; i<num; i++) {
		nng_msg_free(mq[i]);
	}

	now = nnl_now();
	nnl_msg_get(mp, &mq[0]);
	for(int i=1; i<num; i++) {
		nnl_msg_get(mp, &mq[i]);
	}
	debug("[%ld]", nnl_now()-now);
	for(int i=0; i<num; i++) {
		nnl_msg_put(mp, &mq[i]);
	}
}

RUN_TESTS(test_msg_pool)
// RUN_TESTS(test_compare_malloc_msg_pool_get)
