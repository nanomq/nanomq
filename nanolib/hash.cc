#include <unordered_map>
#include <cstring>
#include <mutex>
#include <cstdlib>
#include "include/dbg.h"
#include "include/hash.h"

using namespace std;

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



mqtt_hash<int, char*> _mqtt_hash;

/*
** 
*/
void push_val(int key, char *val)
{
	_mqtt_hash[key] = val;

}

/*
** 
*/
char *get_val(int key)
{
	return _mqtt_hash.get(key);
}

/*
** 
*/
void del_val(int key) 
{
	_mqtt_hash.del(key);

}

mqtt_hash<char *, topic_queue *> _topic_hash;

struct topic_queue *new_topic_queue(char *val)
{
	struct topic_queue *tq = NULL;
	int len = strlen(val);

	tq = (struct topic_queue*)malloc(sizeof(struct topic_queue));
	if (!tq) {
		fprintf(stderr, "zmalloc: Out of memory\n");
		fflush(stderr);
		abort();

	}
	tq->topic = (char*)malloc(sizeof(char)*(len+1));
	if (!tq->topic) {
		fprintf(stderr, "zmalloc: Out of memory\n");
		fflush(stderr);
		abort();

	}
	memcpy(tq->topic, val, len);
	tq->topic[len] = '\0';
	tq->next = NULL;

	return tq;
}

void delete_topic_queue(struct topic_queue *tq)
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
** 
*/
void add_topic(char *id, char *val)
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
**
*/
struct topic_queue *get_topic(char *id) 
{
	if (_topic_hash[id]) {
		return _topic_hash[id];
	} 

	return NULL;
}

/*
**
*/
void del_topic_one(char *id, char *topic)
{
	struct topic_queue *tt = _topic_hash[id];
	struct topic_queue *tb = NULL;

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
**
*/
void del_topic_all(char *id)
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
**
*/
bool check_id(char *id)
{
	return _topic_hash.find(id);
}


mqtt_hash<uint32_t, char *> _pipe_hash;

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

char *get_client_id(uint32_t pipe_id) 
{
	return _pipe_hash[pipe_id];
}

bool check_pipe_id(uint32_t pipe_id)
{
	return _pipe_hash.find(pipe_id);
}


