#ifndef HASH_TABLE_H
#define HASH_TABLE_H

#include "cvector.h"
#include <stdbool.h>
#include <stdint.h>

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


void dbhash_add_alias(int alias, const char *topic);

const char *dbhash_find_alias(int alias);

void dbhash_del_alias(int alias);


void dbhash_insert_topic(uint32_t id, char *val);

bool dbhash_check_topic(uint32_t id, char *val);

struct topic_queue *dbhash_get_topic_queue(uint32_t id);

void dbhash_del_topic(uint32_t id, char *topic);

void dbhash_del_topic_queue(uint32_t id);

bool dbhash_check_id(uint32_t id);

void dbhash_print_topic_queue(uint32_t id);

topic_queue **dbhash_get_topic_queue_all(size_t *sz);

void dbhash_cache_topic_all(uint32_t pid, uint32_t cid);

void dbhash_restore_topic_all(uint32_t cid, uint32_t pid);

struct topic_queue *dbhash_get_cached_topic(uint32_t cid);

void dbhash_del_cached_topic_all(uint32_t key);

bool dbhash_cached_check_id(uint32_t key);


#endif
