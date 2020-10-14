#ifndef HASH_H
#define HASH_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif


struct topic_queue {
	char               *topic;
	struct topic_queue *next;
};

typedef struct topic_queue topic_queue;

struct msg_queue {
	char             *msg;
	struct msg_queue *next;
};

typedef struct msg_queue msg_queue;

void push_val(int key, char *val);

char *get_val(int key);

void del_val(int key); 

// @obj. _topic_hash

void add_topic(char *id, char *val);

struct topic_queue *get_topic(char *id); 

void del_topic_one(char *id, char *topic);

void del_topic_all(char *id);

bool check_id(char *id);

// @obj. _pipe_hash

void add_pipe_id(uint32_t pipe_id, char *client_id);

void del_pipe_id(uint32_t pipe_id);

char *get_client_id(uint32_t pipe_id); 

bool check_pipe_id(uint32_t pipe_id);

// @obj. _msg_queue_hash

void add_msg_queue(char *id, char *msg);

void del_msg_queue_all(char *id);

bool check_msg_queue_clientid(char *id);

struct msg_queue * get_msg_queue(char *id);

#ifdef __cplusplus
}
#endif

#endif
