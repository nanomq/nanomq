#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "../include/msg_pool.h"
#include "../include/dbg.h"

char * test_msg_pool()
{
	nnl_msg_pool * mp;
	nng_msg * msg, * msgs[65];
	uint8_t rv = 0;
	log("create msg pool?");
	CHECK(nnl_msg_pool_create(&mp) == 0);
	log("get?");
	CHECK(nnl_msg_get(mp, &msg) == 0);
	log("used 1 ?");
	CHECK(nnl_msg_pool_used(mp) == 1);
	log("put?");
	CHECK(nnl_msg_put(mp, &msg) == 0);
	log("used 0 ?");
	CHECK(nnl_msg_pool_used(mp) == 0);
	log("resize 32 ?");
	CHECK(nnl_msg_pool_resize(mp, 32) == 0);
	log("capacity 32?");
	CHECK(nnl_msg_pool_capacity(mp) == 32);
	log("empty?");
	CHECK(nnl_msg_pool_empty(mp));
	log("full?");
	CHECK(nnl_msg_pool_full(mp));
	log("boundary test1 for get msg ?");
	rv = 0;
	for(int i=0; i<65; i++){
		rv |= nnl_msg_get(mp, &msgs[i]);
		log("rv: [%d] address [%p]", rv, msgs[i]);
	}
	rv = 0;
	log("boundary test1 for put msg?");
	for(int i=0; i<65; i++){
		rv |= nnl_msg_put(mp, &msgs[i]);
		log("rv: [%d] address [%p]", rv, msgs[i]);
	}
	log("resize 64 ?");
	CHECK(nnl_msg_pool_resize(mp, 64) == 0);
	log("capacity 64 ?");
	CHECK(nnl_msg_pool_capacity(mp) == 64);
	log("boundary test2 for get msg ?");
	rv = 0;
	for(int i=0; i<32; i++){
		rv |= nnl_msg_get(mp, &msgs[i]);
		log("rv: [%d] address [%p]", rv, msgs[i]);
	}
	log("resize 32 ?");
	CHECK(nnl_msg_pool_resize(mp, 32) == 0);
	log("capacity 32 ?");
	CHECK(nnl_msg_pool_capacity(mp) == 32);
	rv = 0;
	log("boundary test2 for put msg?");
	for(int i=0; i<32; i++){
		rv |= nnl_msg_put(mp, &msgs[i]);
		log("rv: [%d] address [%p]", rv, msgs[i]);
	}
	log("delete msg pool.");
	nnl_msg_pool_delete(mp);
	return NULL;
}

RUN_TESTS(test_msg_pool)
