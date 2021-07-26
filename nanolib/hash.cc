//
// Copyright 2020 NanoMQ Team, Inc. <jaylin@emqx.io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//
#include <unordered_map>
#include <cstring>
#include <mutex>
#include <cstdlib>
#include "include/dbg.h"
#include "include/hash.h"

using namespace std;

/*
 * A thread safe hash table
 * baseed on unordered_map
 */ 

template<typename K, typename V>
class mqtt_hash {
	public:
		typedef typename unordered_map<K, V>::iterator iterator;

		V &operator [](const K &_key)
		{
			lock_guard<mutex> lk(_mtx);
			return hash_map[_key];
		}

		V get(const K &_key)
		{
			lock_guard<mutex> lk(_mtx);
			return hash_map[_key];
		}

		void set(const K &_key, const V &_val) 
		{
			lock_guard<mutex> lk(_mtx);
			hash_map[_key] = _val;
		}

		void del(const K &_key) 
		{
			lock_guard<mutex> lk(_mtx);
			mqtt_hash<K, V>::iterator iter = hash_map.find(_key);

			if (iter != hash_map.end()) {
				hash_map.erase(iter);
			}
		}

		bool find(const K &_key)
		{
			mqtt_hash<K, V>::iterator iter = hash_map.begin();
			iter = hash_map.find(_key);

			if (iter != hash_map.end()) {
				return true;
			}
			return false;
		}


	private:
		unordered_map<K, V> hash_map;
		mutex _mtx;

};

/*
 * @obj. Test.
 */

mqtt_hash<int, char*> _mqtt_hash;

/*
 * @obj. Test.
 */

void push_val(int key, char *val)
{
	_mqtt_hash[key] = val;

}

/*
 * @obj. Test.
 */

char *get_val(int key)
{
	return _mqtt_hash.get(key);
}

/*
 * @obj. Test.
 */

void del_val(int key) 
{
	_mqtt_hash.del(key);

}

/*
 * @obj. _topic_hash.
 * @key. clientid.
 * @val. topic_queue.
 */

// mqtt_hash<char *, topic_queue *> _topic_hash;
// 
// static struct topic_queue *new_topic_queue(char *val)
// {
// 	struct topic_queue *tq = NULL;
// 	int len = strlen(val);
// 
// 	tq = (struct topic_queue*)malloc(sizeof(struct topic_queue));
// 	if (!tq) {
// 		fprintf(stderr, "malloc: Out of memory\n");
// 		fflush(stderr);
// 		abort();
// 
// 	}
// 	tq->topic = (char*)malloc(sizeof(char)*(len+1));
// 	if (!tq->topic) {
// 		fprintf(stderr, "malloc: Out of memory\n");
// 		fflush(stderr);
// 		abort();
// 
// 	}
// 	memcpy(tq->topic, val, len);
// 	tq->topic[len] = '\0';
// 	tq->next = NULL;
// 
// 	return tq;
// }
// 
// static void delete_topic_queue(struct topic_queue *tq)
// {
// 	if (tq) {
// 		if (tq->topic) {
// 			log("delete topic:%s", tq->topic);
// 			free(tq->topic);
// 			tq->topic = NULL;
// 		}
// 		free(tq);
// 		tq = NULL;
// 	}
// 	return;
// }
// 
// /*
//  * @obj. _topic_hash.
//  * @key.clientid.
//  * @val. topic_queue.
//  */
// 
// void add_topic(char *id, char *val)
// {
// 	struct topic_queue *ntq = new_topic_queue(val);
// 	struct topic_queue *tq = _topic_hash[id];
// 	if (tq == NULL) {
// 		_topic_hash[id] = ntq;
// 		log("add_topic:%s",_topic_hash[id]->topic);
// 	} else {
//                 struct topic_queue *tmp = tq->next;
// 		tq->next = ntq;
// 		ntq->next = tmp;
// 		log("add_topic:%s", tq->next->topic);
// 	}
// 
// }
// 
// /*
//  * @obj. _topic_hash.
//  * @key.clientid.
//  */
// 
// struct topic_queue *get_topic(char *id) 
// {
// 	if (_topic_hash[id]) {
// 		return _topic_hash[id];
// 	} 
// 
// 	return NULL;
// }
// 
// /*
//  * @obj. _topic_hash.
//  * @key.clientid.
//  */
// 
// void del_topic_one(char *id, char *topic)
// {
// 	struct topic_queue *tt = _topic_hash[id];
// 	struct topic_queue *tb = NULL;
// 
// 	if (!strcmp(tt->topic, topic) && tt->next == NULL) {
// 		_topic_hash.del(id);
// 		delete_topic_queue(tt);
// 		return;
// 	}
// 
// 	if (!strcmp(tt->topic, topic)) {
// 		_topic_hash[id] = tt->next;
// 		delete_topic_queue(tt);
// 		return;
// 	}
// 
// 	while (tt) {
// 		if (!strcmp(tt->topic, topic)) {
// 			if (tt->next == NULL) {
// 				tb->next = NULL;
// 			} else {
// 				tb->next = tt->next;
// 			}
// 			break;
// 		}
// 		tb = tt;
// 		tt = tt->next;
// 	}
// 
// 	delete_topic_queue(tt);
// 
// 	return;
// }
// 
// /*
//  * @obj. _topic_hash.
//  * @key.clientid.
//  */
// 
// void del_topic_all(char *id)
// {
// 	struct topic_queue *tq = _topic_hash[id];
// 	_topic_hash.del(id);
// 	while (tq) {
// 		struct topic_queue *tt = tq;
// 		tq = tq->next;
// 		delete_topic_queue(tt);
// 	}
// 	return;
// }
// 
// /*
//  * @obj. _topic_hash.
//  */
// 
// bool check_id(char *id)
// {
// 	return _topic_hash.find(id);
// }


/*
 * @obj. _topic_hash.
 * @key. pipe_id.
 * @val. topic_queue.
 */

mqtt_hash<uint32_t, topic_queue *> _topic_hash;

static struct topic_queue *new_topic_queue(char *val)
{
	struct topic_queue *tq = NULL;
	int len = strlen(val);

	tq = (struct topic_queue*)malloc(sizeof(struct topic_queue));
	if (!tq) {
		fprintf(stderr, "malloc: Out of memory\n");
		fflush(stderr);
		abort();

	}
	tq->topic = (char*)malloc(sizeof(char)*(len+1));
	if (!tq->topic) {
		fprintf(stderr, "malloc: Out of memory\n");
		fflush(stderr);
		abort();

	}
	memcpy(tq->topic, val, len);
	tq->topic[len] = '\0';
	tq->next = NULL;

	return tq;
}

static void delete_topic_queue(struct topic_queue *tq)
{
	if (tq) {
		if (tq->topic) {
			log("delete topic:%s", tq->topic);
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

void add_topic(uint32_t id, char *val)
{
	struct topic_queue *ntq = new_topic_queue(val);
	struct topic_queue *tq = _topic_hash[id];
	if (tq == NULL) {
		_topic_hash[id] = ntq;
		log("add_topic:%s",_topic_hash[id]->topic);
	} else {
		struct topic_queue *tmp = tq->next;
		tq->next = ntq;
		ntq->next = tmp;
		log("add_topic:%s", tq->next->topic);
	}

}

/*
 * @obj. _topic_hash.
 * @key. pipe_id.
 * @val. topic.
 */

bool check_topic(uint32_t id, char *val) 
{
	if (!check_id(id)) {
		return false;
	}

	struct topic_queue *tq = _topic_hash[id];

	while (tq != NULL) {
		if (!strcmp(tq->topic, val)) {
			return true;
		}
		tq = tq->next;
	}

	return false;
}

/*
 * @obj. _topic_hash.
 * @key. pipe_id.
 */

struct topic_queue *get_topic(uint32_t id) 
{
	if (_topic_hash[id]) {
		return _topic_hash[id];
	} 

	return NULL;
}

/*
 * @obj. _topic_hash.
 * @key. pipe_id.
 */

void del_topic_one(uint32_t id, char *topic)
{
	struct topic_queue *tt = _topic_hash[id];
	struct topic_queue *tb = NULL;

	if (tt == NULL) {
		return;
	}
	if (!strcmp(tt->topic, topic) && tt->next == NULL) {
		_topic_hash.del(id);
		delete_topic_queue(tt);
		return;
	}

	if (!strcmp(tt->topic, topic)) {
		_topic_hash[id] = tt->next;
		delete_topic_queue(tt);
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

	return;
}

/*
 * @obj. _topic_hash.
 * @key.pipe_id.
 */

void del_topic_all(uint32_t id)
{
	struct topic_queue *tq = _topic_hash[id];
	_topic_hash.del(id);
	while (tq) {
		struct topic_queue *tt = tq;
		tq = tq->next;
		delete_topic_queue(tt);
	}
	return;
}

/*
 * @obj. _topic_hash.
 */

bool check_id(uint32_t id)
{
	return _topic_hash.find(id);
}

/* 
 * @obj. _topic_hash. 
 * @key. pipe_id.
 */

void print_topic_all(uint32_t id)
{
	struct topic_queue *tq = _topic_hash[id];
	int t_num = 0;
	while(tq) {
		log("Topic number %d, topic subscribed: %s.", ++t_num, tq->topic);
		tq = tq->next;
	}
}

/*
 * @obj. _cached_topic_hash.
 * @key. (DJBhashed) client_id.
 * @val. cached_topic_queue.
 */

mqtt_hash<uint32_t, topic_queue *> _cached_topic_hash;

/*
 * @obj. _topic_hash.
 * @key. pipe_id.
 * @obj. _cached_topic_hash.
 * @key. (DJBhashed) client_id.
 */

void cache_topic_all(uint32_t pid, uint32_t cid)
{
	struct topic_queue *tq_in_topic_hash = _topic_hash[pid];
	if (cached_check_id(cid)) {
		log("unexpected: cached hash instance is not vacant");
		del_cached_topic_all(cid);
	}
	_cached_topic_hash[cid] = tq_in_topic_hash;
	_topic_hash.del(pid);
}

/*
 * @obj. _cached_topic_hash.
 * @key. (DJBhashed) client_id.
 * @obj. _topic_hash.
 * @key. pipe_id.
 */

void restore_topic_all(uint32_t cid, uint32_t pid) 
{
	struct topic_queue *tq_in_cached = _cached_topic_hash[cid];
	if (check_id(pid)) {
		log("unexpected: hash instance is not vacant");
		del_topic_all(pid);
	}
	_topic_hash[pid] = tq_in_cached;
	_cached_topic_hash.del(cid);
}

/*
 * @obj. _cached_topic_hash.
 * @key. (DJBhashed) client_id.
 * @val. topic_queue
 */

static void delete_cached_topic_one(struct topic_queue *ctq)
{
	if (ctq) {
		if (ctq->topic) {
			log("delete topic:%s", ctq->topic);
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

struct topic_queue *get_cached_topic(uint32_t cid) 
{
	if (_cached_topic_hash[cid]) {
		return _cached_topic_hash[cid];
	}

	return NULL;
}

/*
 * @obj. _cached_topic_hash.
 * @key. (DJBhashed) client_id.
 */

void del_cached_topic_all(uint32_t cid)
{
	struct topic_queue *ctq = _cached_topic_hash[cid];
	_cached_topic_hash.del(cid);
	while (ctq) {
		struct topic_queue *tt = ctq;
		ctq = ctq->next;
		delete_cached_topic_one(tt);
	}
	return;
}

/*
 * @obj. _cached_topic_hash.
 * @key. (DJBhashed) client_id.
 */

bool cached_check_id(uint32_t key)
{
	return _cached_topic_hash.find(key);
}


/*
 * @obj. _pipe_hash.
 * @key. pipe_id.
 * @val. clientid.
 */

mqtt_hash<uint32_t, char *> _pipe_hash;

/*
 * @obj. _pipe_hash.
 */

void add_pipe_id(uint32_t pipe_id, char *client_id)
{
	_pipe_hash[pipe_id] = client_id;
	log("add_pipe_id %d, client_id %s", pipe_id, _pipe_hash[pipe_id]);
	return;
}

void del_pipe_id(uint32_t pipe_id)
{
#ifdef NOLOG
#else
	char *res = _pipe_hash[pipe_id];
#endif
	log("del_pipe_id %d, client_id %s", pipe_id, res);
	_pipe_hash.del(pipe_id);
	return;
	
}

/*
 * @obj. _pipe_hash.
 */

char *get_client_id(uint32_t pipe_id) 
{
	return _pipe_hash[pipe_id];
}

/*
 * @obj. _pipe_hash.
 */

bool check_pipe_id(uint32_t pipe_id)
{
	return _pipe_hash.find(pipe_id);
}

/*
 * @obj. _msg_queue_hash.
 * @key. clientid.
 * @val. msg_queue.
 * Store the offline msg which qos>0 when clean_start==0
 */

mqtt_hash<char *, struct msg_queue *> _msg_queue_hash;

static struct msg_queue *new_msg_queue(char *val)
{
	struct msg_queue *mq = NULL;
	int len = strlen(val);

	mq = (struct msg_queue*)malloc(sizeof(struct msg_queue));
	if (!mq) {
		fprintf(stderr, "zmalloc: Out of memory\n");
		fflush(stderr);
		abort();
	}

	mq->msg = (char*)malloc(sizeof(char)*(len+1));
	if (!mq->msg) {
		fprintf(stderr, "zmalloc: Out of memory\n");
		fflush(stderr);
		abort();
	}

	memcpy(mq->msg, val, len);
	mq->msg[len] = '\0';
	mq->next = NULL;

	return mq;
}

static void delete_msg_queue(struct msg_queue *mq)
{
	if (mq) {
		if (mq->msg) {
			log("delete topic:%s", mq->msg);
			free(mq->msg);
			mq->msg = NULL;
		}
		free(mq);
		mq = NULL;
	}
	return;
}

/*
 * @obj. _msg_queue_hash
 */

void add_msg_queue(char *id, char *msg)
{
	struct msg_queue *nmq = new_msg_queue(msg);
	struct msg_queue *mq = _msg_queue_hash[id];
	if (mq == NULL) {
		_msg_queue_hash[id] = nmq;
		log("add_topic:%s",_msg_queue_hash[id]->msg);
	} else {
        struct msg_queue *tmp = mq->next;
		mq->next = nmq;
		nmq->next = tmp;
		log("add_topic:%s", mq->next->msg);
	}
}

/*
 * @obj. _msg_queue_hash
 */

void del_msg_queue_all(char *id)
{
	struct msg_queue *mq = _msg_queue_hash[id];
	_msg_queue_hash.del(id);
	while (mq) {
		struct msg_queue *tt = mq;
		mq = mq->next;
		delete_msg_queue(tt);
	}
	return;
}

/*
 * @obj. _msg_queue_hash
 */

bool check_msg_queue_clientid(char *id)
{
	return _msg_queue_hash.find(id);
}

/*
 * @obj. _msg_queue_hash
 */

struct msg_queue * get_msg_queue(char *id)
{
	if(check_msg_queue_clientid(id)){
		return _msg_queue_hash[id];
	}
	return NULL;
}
