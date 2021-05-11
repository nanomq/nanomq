#ifndef HASH_H
#define HASH_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct topic_queue {
	char *              topic;
	struct topic_queue *next;
};

typedef struct topic_queue topic_queue;

struct msg_queue {
	char *            msg;
	struct msg_queue *next;
};

typedef struct msg_queue msg_queue;

void push_val(int key, char *val);

char *get_val(int key);

void del_val(int key);

// @obj. _topic_hash

void add_topic(uint32_t id, char *val);

bool check_topic(uint32_t id, char *val);

struct topic_queue *get_topic(uint32_t id); 

void del_topic_one(uint32_t id, char *topic);

void del_topic_all(uint32_t id);

bool check_id(uint32_t id);

void print_topic_all(uint32_t id);

// @obj. _cached_topic_hash

void cache_topic_all(uint32_t pid, uint32_t cid);

void restore_topic_all(uint32_t cid, uint32_t pid);

struct topic_queue *get_cached_topic(uint32_t cid);

void del_cached_topic_all(uint32_t key);

bool cached_check_id(uint32_t key);

// @obj. _pipe_hash

void add_pipe_id(uint32_t pipe_id, char *client_id);

void del_pipe_id(uint32_t pipe_id);

char *get_client_id(uint32_t pipe_id);

bool check_pipe_id(uint32_t pipe_id);

// @obj. _msg_queue_hash

void add_msg_queue(char *id, char *msg);

void del_msg_queue_all(char *id);

bool check_msg_queue_clientid(char *id);

struct msg_queue *get_msg_queue(char *id);

#ifdef __cplusplus
}
#endif

#endif
