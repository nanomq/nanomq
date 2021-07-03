#ifndef MQTT_DB_H
#define MQTT_DB_H

#include "cvector.h"
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

typedef enum { Hash, Vec } type;
typedef struct db_node db_node;

typedef struct s_client {
	// char			*id;
	uint32_t pipe_id;
	void *   ctxt;
} s_client;

typedef struct retain_msg {
	uint8_t qos;
	bool    exist;
	char *  m;
	void *  message;
} retain_msg;

typedef struct db_node {
	char *      topic;
	int         plus;
	int         well;
	retain_msg *retain;
	cvector(s_client *) clients;
	cvector(db_node *) child;
	pthread_rwlock_t rwlock;
} db_node;

typedef struct {
	db_node *        root;
	pthread_rwlock_t rwlock;
} db_tree;

/**
 * @brief node_cmp - A callback to compare different node
 * @param x - normally x is db_node
 * @param y - y is topic we want to compare
 * @return 0, minus or plus, based on strcmp
 */
static inline int
node_cmp(void *x_, void *y_)
{
	char *   y     = (char *) y_;
	db_node *ele_x = (db_node *) x_;
	return strcmp(ele_x->topic, y);
}

/**
 * @brief client_cmp - A callback to compare different client
 * @param x - normally x is s_client
 * @param y - normally x is s_client
 * @return 0, minus or plus, based on strcmp
 */
static inline int
client_cmp(void *x_, /*char *y,*/ void *y_)
{
	uint32_t *pipe_id = (uint32_t *) y_;
	s_client *ele_x   = (s_client *) x_;
	// printf("\ncompare: %d, %d\n", ele_x->pipe_id, *pipe_id);
	return *pipe_id - ele_x->pipe_id;
}

/* Create a db_tree */
void create_db_tree(db_tree **db);

/* Delete a db_tree */
void destory_db_tree(db_tree *db);

void print_db_tree(db_tree *db);

void *search_and_insert(
    db_tree *db, char *topic, char *id, void *ctxt, uint32_t pipe_id);

void *search_and_delete(db_tree *db, char *topic, uint32_t pipe_id);

void **search_client(db_tree *db, char *topic);

void *search_insert_retain(db_tree *db, char *topic, retain_msg *ret_msg);

void *search_delete_retain(db_tree *db, char *topic);

retain_msg **search_retain(db_tree *db, char *topic);

//
// void del_all(uint32_t pipe_id, void *db);
//
// /* Free node memory */
// void free_node(struct db_node *node);
//
// /* Parsing topic from char* with '/' to char** */
// char **topic_parse(char *topic);
//

/* A hash table, clientId or alias as key, topic as value */
char *hash_check_alias(int alias);

void hash_add_alias(int alias, char *topic_data);

void hash_del_alias(int alias);

// char *search_hash_node(char *topic);

#endif
