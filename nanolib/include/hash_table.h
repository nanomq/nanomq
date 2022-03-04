#ifndef HASH_TABLE_H
#define HASH_TABLE_H

#include "cvector.h"
#include "dbg.h"
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

// atpair is alias topic pair
typedef struct dbhash_atpair_s dbhash_atpair_t;

struct dbhash_atpair_s {
	uint32_t alias;
	char *   topic;
};

typedef struct dbhash_ptpair_s dbhash_ptpair_t;

// ptpair is pipe topic pair
struct dbhash_ptpair_s {
	uint32_t pipe;
	char *   topic;
};

/**
 * @brief alias_cmp - A callback to compare different alias
 * @param x - normally x is pointer of dbhash_atpair_t
 * @param y - normally y is pointer of alias
 * @return 0, minus or plus
 */
static inline int
alias_cmp(void *x_, void *y_)
{
	uint32_t *       alias = (uint32_t *) y_;
	dbhash_atpair_t *ele_x = (dbhash_atpair_t *) x_;
	return *alias - ele_x->alias;
}

void dbhash_init_alias_table(void);

void dbhash_destroy_alias_table(void);
// This function do not verify value of alias and topic,
// therefore you should make sure alias and topic is
// not illegal.
void dbhash_insert_atpair(uint32_t pipe_id, uint32_t alias, const char *topic);

const char *dbhash_find_atpair(uint32_t pipe_id, uint32_t alias);

void dbhash_del_atpair_queue(uint32_t pipe_id);

void dbhash_init_pipe_table(void);

void dbhash_destroy_pipe_table(void);

void dbhash_insert_topic(uint32_t id, char *val);

bool dbhash_check_topic(uint32_t id, char *val);

struct topic_queue *dbhash_get_topic_queue(uint32_t id);

void dbhash_del_topic(uint32_t id, char *topic);

void dbhash_del_topic_queue(uint32_t id);

bool dbhash_check_id(uint32_t id);

void dbhash_print_topic_queue(uint32_t id);

topic_queue **dbhash_get_topic_queue_all(size_t *sz);

dbhash_ptpair_t *dbhash_ptpair_alloc(uint32_t p, char *t);

void dbhash_ptpair_free(dbhash_ptpair_t *pt);

dbhash_ptpair_t **dbhash_get_ptpair_all(void);

size_t dbhash_get_pipe_cnt(void);

void dbhash_init_cached_table(void);
void dbhash_destroy_cached_table(void);

void dbhash_cache_topic_all(uint32_t pid, uint32_t cid);

void dbhash_restore_topic_all(uint32_t cid, uint32_t pid);

struct topic_queue *dbhash_get_cached_topic(uint32_t cid);

void dbhash_del_cached_topic_all(uint32_t key);

bool dbhash_cached_check_id(uint32_t key);

#endif
