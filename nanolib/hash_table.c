//
// Copyright 2020 NanoMQ Team, Inc. <jaylin@emqx.io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//
#include "include/hash_table.h"
#include "include/dbg.h"
#include "include/khash.h"
#include "include/zmalloc.h"
#include <pthread.h>

#define dbhash_check_init(name, h, lock)           	\
	if (h == NULL) {               			\
		h = kh_init(name);     			\
		pthread_rwlock_init(&lock, NULL); 	\
	}                              


KHASH_MAP_INIT_INT(alias_table, char*)
static pthread_rwlock_t alias_lock;
static khash_t(alias_table) *ah = NULL;

void
dbhash_add_alias(int a, const char *t)
{
	int absent;
	dbhash_check_init(alias_table, ah, alias_lock);
	pthread_rwlock_wrlock(&alias_lock);
	khint_t k = kh_put(alias_table, ah, a, &absent);
	if (absent) {
		kh_value(ah, k) = zstrdup(t);
	}
	pthread_rwlock_unlock(&alias_lock);
	return;
}

const char *
dbhash_find_alias(int a)
{

	dbhash_check_init(alias_table, ah, alias_lock);
	pthread_rwlock_wrlock(&alias_lock);
	khint_t k = kh_get(alias_table, ah, a);
	const char *t = kh_val(ah, k);
	pthread_rwlock_unlock(&alias_lock);
	return t;
}

void
dbhash_del_alias(int a)
{
	dbhash_check_init(alias_table, ah, alias_lock);
	pthread_rwlock_wrlock(&alias_lock);
	kh_del(alias_table, ah, a);
	pthread_rwlock_unlock(&alias_lock);
	// if (kh_size(ah) == 0) {
	// 	kh_destroy(alias_table, ah);
	// 	ah = NULL;
	// }
}


KHASH_MAP_INIT_INT(pipe_table, topic_queue *)
static pthread_rwlock_t pipe_lock;
static khash_t(pipe_table) *ph = NULL;

topic_queue **
dbhash_get_topic_queue_all(size_t *sz)
{
	dbhash_check_init(pipe_table, ph, pipe_lock);
	pthread_rwlock_wrlock(&pipe_lock);
	size_t size = kh_size(ph);

	topic_queue **res =
	    (topic_queue **) malloc(size * sizeof(topic_queue *));

	for (khint_t k = kh_begin(ph); k != kh_end(ph); ++k) {
    	      if (kh_exist(ph, k)) {
      	      	*res++ = kh_value(ph, k);
	      }
	}
	pthread_rwlock_unlock(&pipe_lock);

	*sz = size;
	return res;
}

static struct topic_queue *
new_topic_queue(char *val)
{
	struct topic_queue *tq  = NULL;
	int                 len = strlen(val);

	tq = (struct topic_queue *) malloc(sizeof(struct topic_queue));
	if (!tq) {
		fprintf(stderr, "malloc: Out of memory\n");
		fflush(stderr);
		abort();
	}
	tq->topic = (char *) malloc(sizeof(char) * (len + 1));
	if (!tq->topic) {
		fprintf(stderr, "malloc: Out of memory\n");
		fflush(stderr);
		abort();
	}
	memcpy(tq->topic, val, len);
	tq->topic[len] = '\0';
	tq->next       = NULL;

	return tq;
}

static void
delete_topic_queue(struct topic_queue *tq)
{
	if (tq) {
		if (tq->topic) {
			log_info("delete topic:%s", tq->topic);
			free(tq->topic);
			tq->topic = NULL;
		}
		free(tq);
		tq = NULL;
	}
	return;
}

/*
 * @obj. _topic_hash.
 * @key. pipe_id.
 * @val. topic_queue.
 */

void
dbhash_insert_topic(uint32_t id, char *val)
{
	struct topic_queue *ntq = new_topic_queue(val);
	struct topic_queue *tq  = NULL;
	dbhash_check_init(pipe_table, ph, pipe_lock);
	pthread_rwlock_wrlock(&pipe_lock);
	khint_t k = kh_get(pipe_table, ph, id);
	// Pipe id is find in hash table.
	if (k != kh_end(ph)) {
		tq = kh_val(ph, k);
		struct topic_queue *tmp = tq->next;
		tq->next                = ntq;
		ntq->next               = tmp;
	} else {
		// If not find pipe id in this hash table, we add a new one.
		int absent;
		khint_t l = kh_put(pipe_table, ph, id, &absent);
		if (absent) {
			kh_val(ph, l) = ntq;
		}
	}
	pthread_rwlock_unlock(&pipe_lock);
}

/*
 * @obj. _topic_hash.
 * @key. pipe_id.
 * @val. topic.
 */

bool
dbhash_check_topic(uint32_t id, char *val)
{

	dbhash_check_init(pipe_table, ph, pipe_lock);
	if (!dbhash_check_id(id)) {
		return false;
	}

	bool ret = false;
	pthread_rwlock_wrlock(&pipe_lock);
	struct topic_queue *tq    = NULL;
	khint_t k = kh_get(pipe_table, ph, id);
	if (k != kh_end(ph)) {
		tq = kh_val(ph, k);
	}

	while (tq != NULL) {
		if (!strcmp(tq->topic, val)) {
			ret = true;
			break;
		}
		tq = tq->next;
	}
	pthread_rwlock_unlock(&pipe_lock);

	return ret;
}

/*
 * @obj. _topic_hash.
 * @key. pipe_id.
 */

struct topic_queue *
dbhash_get_topic_queue(uint32_t id)
{

	dbhash_check_init(pipe_table, ph, pipe_lock);
	struct topic_queue *ret = NULL;

	pthread_rwlock_wrlock(&pipe_lock);
	khint_t k = kh_get(pipe_table, ph, id);
	if (k != kh_end(ph)) {
		ret = kh_val(ph, k);
	}
	pthread_rwlock_unlock(&pipe_lock);

	return ret;
}

/*
 * @obj. _topic_hash.
 * @key. pipe_id.
 */

// TODO
void
dbhash_del_topic(uint32_t id, char *topic)
{
	dbhash_check_init(pipe_table, ph, pipe_lock);
	struct topic_queue *tt = NULL;
	struct topic_queue *tb = NULL;

	pthread_rwlock_wrlock(&pipe_lock);
	khint_t k = kh_get(pipe_table, ph, id);
	if (k != kh_end(ph)) {
		tt = kh_val(ph, k);
	}

	if (tt == NULL) {
		pthread_rwlock_unlock(&pipe_lock);
		return;
	}
	// If topic is the first one and no other topic follow,
	// we should delete the topic and delete pipe id from 
	// this hash table.
	if (!strcmp(tt->topic, topic) && tt->next == NULL) {
		kh_del(pipe_table, ph, k);
		delete_topic_queue(tt);
		pthread_rwlock_unlock(&pipe_lock);
		return;
	}

	// If topic is the first one with other topic follow,
	// we should delete it and assign the next pointer
	// to this key.
	if (!strcmp(tt->topic, topic)) {
		kh_val(ph, k) = tt->next;
		delete_topic_queue(tt);
		pthread_rwlock_unlock(&pipe_lock);
		return;
	}

	while (tt) {
		if (!strcmp(tt->topic, topic)) {
			if (tt->next == NULL) {
				tb->next = NULL;
			} else {
				tb->next = tt->next;
			}
			break;
		}
		tb = tt;
		tt = tt->next;
	}

	delete_topic_queue(tt);

	pthread_rwlock_unlock(&pipe_lock);
	return;
}

/*
 * @obj. _topic_hash.
 * @key.pipe_id.
 */

void
dbhash_del_topic_queue(uint32_t id)
{
	struct topic_queue *tq = NULL;
	dbhash_check_init(pipe_table, ph, pipe_lock);
	pthread_rwlock_wrlock(&pipe_lock);
	khint_t k = kh_get(pipe_table, ph, id);
	if (k != kh_end(ph)) {
		tq = kh_val(ph, k);
		kh_del(pipe_table, ph, k);
	}
	pthread_rwlock_unlock(&pipe_lock);

	while (tq) {
		struct topic_queue *tt = tq;
		tq                     = tq->next;
		delete_topic_queue(tt);
	}

	return;
}

/*
 * @obj. _topic_hash.
 */

bool
dbhash_check_id(uint32_t id)
{
	bool ret = false;
	dbhash_check_init(pipe_table, ph, pipe_lock);
	pthread_rwlock_wrlock(&pipe_lock);
	khint_t k = kh_get(pipe_table, ph, id);
	if (k != kh_end(ph)) {
		ret = true;
	}
	pthread_rwlock_unlock(&pipe_lock);
	return ret;
}

/*
 * @obj. _topic_hash.
 * @key. pipe_id.
 */

void
dbhash_print_topic_queue(uint32_t id)
{
	dbhash_check_init(pipe_table, ph, pipe_lock);
	struct topic_queue *tq    = NULL;
	pthread_rwlock_wrlock(&pipe_lock);
	khint_t k = kh_get(pipe_table, ph, id);
	if (k != kh_end(ph)) {
		tq = kh_val(ph, k);
	}

	int t_num = 0;
	while (tq) {
		printf("Topic number %d, topic subscribed: %s.\n", ++t_num,
		    tq->topic);
		tq = tq->next;
	}
	pthread_rwlock_unlock(&pipe_lock);
}

/*
 * @obj. _cached_topic_hash.
 * @key. (DJBhashed) client_id.
 * @val. cached_topic_queue.
 */

// mqtt_hash<uint32_t, topic_queue *> _cached_topic_hash;
KHASH_MAP_INIT_INT(_cached_topic_hash, topic_queue *)
static khash_t(_cached_topic_hash) *ch = NULL;
static pthread_rwlock_t cached_lock;

/*
 * @obj. _topic_hash.
 * @key. pipe_id.
 * @obj. _cached_topic_hash.
 * @key. (DJBhashed) client_id.
 */

void
dbhash_cache_topic_all(uint32_t pid, uint32_t cid)
{
	dbhash_check_init(pipe_table, ph, pipe_lock);
	dbhash_check_init(_cached_topic_hash, ch, cached_lock);

	// struct topic_queue *tq_in_topic_hash = _topic_hash[pid];
	struct topic_queue *tq_in_topic_hash    = NULL;
	pthread_rwlock_wrlock(&pipe_lock);
	khint_t k = kh_get(pipe_table, ph, pid);
	if (k != kh_end(ph)) {
		tq_in_topic_hash = kh_val(ph, k);
	}
	pthread_rwlock_unlock(&pipe_lock);

	
	pthread_rwlock_wrlock(&cached_lock);
	if (dbhash_cached_check_id(cid)) {
		log_info("unexpected: cached hash instance is not vacant");
		dbhash_del_cached_topic_all(cid);
	}
	int absent;
	khint_t l = kh_put(_cached_topic_hash, ch, cid, &absent);
	kh_val(ch, l) = tq_in_topic_hash;
	pthread_rwlock_unlock(&cached_lock);
	
	pthread_rwlock_wrlock(&pipe_lock);
	kh_del(pipe_table, ph, k);
	pthread_rwlock_unlock(&pipe_lock);
}

/*
 * @obj. _cached_topic_hash.
 * @key. (DJBhashed) client_id.
 * @obj. _topic_hash.
 * @key. pipe_id.
 */

void
dbhash_restore_topic_all(uint32_t cid, uint32_t pid)
{
	dbhash_check_init(pipe_table, ph, pipe_lock);
	dbhash_check_init(_cached_topic_hash, ch, cached_lock);

	struct topic_queue *tq_in_cached = NULL;
	pthread_rwlock_wrlock(&cached_lock);
	khint_t k = kh_get(_cached_topic_hash, ch, cid);
	if (k != kh_end(ch)) {
		tq_in_cached = kh_val(ch, k);

	}
	pthread_rwlock_unlock(&cached_lock);

	if (dbhash_check_id(pid)) {
		log_info("unexpected: hash instance is not vacant");
		dbhash_del_topic_queue(pid);
	}
	int absent;
	pthread_rwlock_wrlock(&pipe_lock);
	khint_t l = kh_put(pipe_table, ph, pid, &absent);
	kh_val(ph, l) = tq_in_cached;
	kh_del(_cached_topic_hash, ch, l);
	pthread_rwlock_unlock(&pipe_lock);
}

/*
 * @obj. _cached_topic_hash.
 * @key. (DJBhashed) client_id.
 * @val. topic_queue
 */

static void
delete_cached_topic_one(struct topic_queue *ctq)
{
	if (ctq) {
		if (ctq->topic) {
			log_info("delete topic:%s", ctq->topic);
			free(ctq->topic);
			ctq->topic = NULL;
		}
		free(ctq);
		ctq = NULL;
	}
	return;
}

/*
 * @obj. _cached_topic_hash.
 * @key. (DJBhashed) client_id.
 * @val. topic_queue
 */

// FIXME Return pointer of topic_queue directly is not safe.
struct topic_queue *
dbhash_get_cached_topic(uint32_t cid)
{
	dbhash_check_init(_cached_topic_hash, ch, cached_lock);
	struct topic_queue *ctq = NULL;
	pthread_rwlock_wrlock(&cached_lock);
	khint_t k = kh_get(_cached_topic_hash, ch, cid);
	if (k != kh_end(ch)) {
		ctq = kh_val(ch, k);
	}
	pthread_rwlock_unlock(&cached_lock);
	return ctq;
}

/*
 * @obj. _cached_topic_hash.
 * @key. (DJBhashed) client_id.
 */

void
dbhash_del_cached_topic_all(uint32_t cid)
{
	dbhash_check_init(_cached_topic_hash, ch, cached_lock);

	struct topic_queue *ctq = NULL;
	pthread_rwlock_wrlock(&cached_lock);
	khint_t k = kh_get(_cached_topic_hash, ch, cid);
	if (k != kh_end(ch)) {
		ctq = kh_val(ch, k);
		kh_del(_cached_topic_hash, ch, k);

	}

	while (ctq) {
		struct topic_queue *tt = ctq;
		ctq                    = ctq->next;
		delete_cached_topic_one(tt);
	}

	pthread_rwlock_unlock(&cached_lock);
	return;
}

/*
 * @obj. _cached_topic_hash.
 * @key. (DJBhashed) client_id.
 */

bool
dbhash_cached_check_id(uint32_t key)
{
	dbhash_check_init(_cached_topic_hash, ch, cached_lock);
	bool ret = false;
	pthread_rwlock_wrlock(&cached_lock);
	khint_t k = kh_get(_cached_topic_hash, ch, key);
	if (k != kh_end(ch)) {
		ret = true;
	}
	pthread_rwlock_unlock(&cached_lock);
	return ret;
}

