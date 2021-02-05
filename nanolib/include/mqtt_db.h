#ifndef MQTT_DB_H
#define MQTT_DB_H

#include <stdbool.h> 
#include <stdint.h>
#include <pthread.h>
#include "cvector.h"

typedef enum {Hash, Vec} type;

typedef struct s_client {
	char			*id;
	void			*ctxt;
} s_client;

struct retain_msg_node {
	struct retain_msg	*ret_msg;
	struct retain_msg_node	*down;
};

struct retain_msg {
	uint8_t			qos;
	bool			exist;
	void			*message;
};

typedef struct db_node db_node;

typedef struct db_node {
	char			*topic;
	int			plus;
	int			well;
	struct retain_msg	*retain;
	cvector(s_client*)	clients;
	cvector(db_node*)       child;
	pthread_rwlock_t	rwlock;	
} db_node;

typedef struct{
	db_node      		*root;
	pthread_rwlock_t	rwlock;	
} db_tree;

/**
 * @brief node_cmp - A callback to compare different node
 * @param x - normally x is db_node 
 * @param y - y is topic we want to compare
 * @return 0, minus or plus, based on strcmp  
 */
static inline int node_cmp(void *x, char *y)
{
        db_node *ele_x = (db_node*) x;
        return strcmp(ele_x->topic, y);
}

/**
 * @brief client_cmp - A callback to compare different client
 * @param x - normally x is s_client 
 * @param y - normally x is s_client 
 * @return 0, minus or plus, based on strcmp 
 */
static inline int client_cmp(void *x, char *y)
{
        s_client *ele_x = (s_client*) x;
        s_client *ele_y = (s_client*) y;
        // printf("\ncompare: %s, %s\n", ele_x->id, ele_y->id);
        return strcmp(ele_x->id, ele_y->id);
}

/* Create a db_tree */
void create_db_tree(db_tree **db);

/* Delete a db_tree */
void destory_db_tree(db_tree *db);

void print_db_tree(db_tree *db);

int search_and_insert(db_tree *db, char *topic, char *id, void *ctxt);
// int search_and_insert(db_tree *db, char *topic, s_client *client);

void *search_and_delete(db_tree *db, char *topic, s_client *client);
// void *search_and_delete(db_tree *db, char *topic, s_client *client);

void **search_client(db_tree *db, char *topic);

// 
// void del_all(uint32_t pipe_id, void *db);
// 
// /* Free node memory */
// void free_node(struct db_node *node);
// 
// /* Parsing topic from char* with '/' to char** */
// char **topic_parse(char *topic);
// 
// void set_retain_msg(struct db_node *node, struct retain_msg *retain);
// 
// struct retain_msg *get_retain_msg(struct db_node *node);
// 
// struct retain_msg_node *search_retain_msg(struct db_node *root,
// 		char **topic_queue);
// 
// void free_retain_node(struct retain_msg_node *msg_node);
// 

/* A hash table, clientId or alias as key, topic as value */ 
char* hash_check_alias(int alias);

void hash_add_alias(int alias, char *topic_data);

void hash_del_alias(int alias);

// char *search_hash_node(char *topic);

#endif
