#ifndef HASH_H
#define HASH_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif


struct topic_queue {
	char				*topic;
	struct topic_queue	*next;
};

void push_val(int key, char *val);

char *get_val(int key);

void del_val(int key); 

void add_topic(char *id, char *val);

struct topic_queue *get_topic(char *id); 

void del_topic_one(char *id, char *topic);

void del_topic_all(char *id);

bool check_id(char *id);


void add_pipe_id(uint32_t pipe_id, char *client_id);

void del_pipe_id(uint32_t pipe_id);

char *get_client_id(uint32_t pipe_id); 

bool check_pipe_id(uint32_t pipe_id);

#ifdef __cplusplus
}
#endif

#endif
