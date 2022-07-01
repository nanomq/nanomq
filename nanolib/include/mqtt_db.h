#ifndef MQTT_DB_H
#define MQTT_DB_H

#include "cvector.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

typedef enum {
	MQTT_VERSION_V311 = 4,
	MQTT_VERSION_V5   = 5,
} mqtt_version_t;

typedef struct {
	uint8_t qos;
	bool    exist;
	char   *m;
	void   *message;
} dbtree_retain_msg;

typedef struct dbtree_node dbtree_node;

struct dbtree_node {
	char	      *topic;
	int                plus;
	int                well;
	dbtree_retain_msg *retain;
	cvector(uint32_t) clients;
	cvector(dbtree_node *) child;
	pthread_rwlock_t rwlock;
};

typedef struct {
	char  *topic;
	char **clients;
	int    cld_cnt;
} dbtree_info;

typedef struct {
	dbtree_node     *root;
	pthread_rwlock_t rwlock;
} dbtree;

/**
 * @brief node_cmp - A callback to compare different node
 * @param x - normally x is dbtree_node
 * @param y - y is topic we want to compare
 * @return 0, minus or plus, based on strcmp
 */
static inline int
node_cmp(void *x_, void *y_)
{
	char        *y     = (char *) y_;
	dbtree_node *ele_x = (dbtree_node *) x_;
	return strcmp(ele_x->topic, y);
}

// TODO
/**
 * @brief ids_cmp - A callback to compare different id
 * @param x - normally x is pointer of id
 * @param y - normally y is pointer of id
 * @return 0, minus or plus, based on strcmp
 */
static inline int
ids_cmp(uint32_t x, uint32_t y)
{
	return y - x;
}

/**
 * @brief dbtree_create - Create a dbtree.
 * @param dbtree - dbtree
 * @return void
 */
void dbtree_create(dbtree **db);

/**
 * @brief dbtree_destory - Destory dbtree tree
 * @param dbtree - dbtree
 * @return void
 */
void dbtree_destory(dbtree *db);

/**
 * @brief dbtree_print - Print dbtree for debug.
 * @param dbtree - dbtree
 * @return void
 */
void dbtree_print(dbtree *db);

/**
 * @brief dbtree_insert_client - check if this
 * topic and pipe id is exist on the tree, if
 * there is not exist, this func will insert node
 * recursively until find all topic then insert
 * client on the node.
 * @param dbtree - dbtree_node
 * @param topic - topic
 * @param pipe_id - pipe id
 * @return
 */
void *dbtree_insert_client(
    dbtree *db, char *topic, uint32_t pipe_id);

/**
 * @brief dbtree_find_client - check if this
 * topic and pipe id is exist on the tree, if
 * there is not exist, return it.
 * @param dbtree - dbtree_node
 * @param topic - topic
 * @param ctxt - data related with pipe_id
 * @param pipe_id - pipe id
 * @return
 */
// void *dbtree_find_client(dbtree *db, char *topic, uint32_t pipe_id);

/**
 * @brief dbtree_delete_client - This function will
 * be called when disconnection and cleansession = 1.
 * check if this topic and client id is exist on the
 * tree, if there is exist, this func will delete
 * related node and client on the tree
 * @param dbtree - dbtree
 * @param topic - topic
 * @param pipe_id - pipe id
 * @return
 */
void *dbtree_delete_client(
    dbtree *db, char *topic, uint32_t pipe_id);

/**
 * @brief dbtree_find_clients_and_cache_msg - Get all
 * subscribers online to this topic
 * @param dbtree - dbtree
 * @param topic - topic
 * @return pipe id array
 */
uint32_t *dbtree_find_clients(dbtree *db, char *topic);

/**
 * @brief dbtree_insert_retain - Insert retain message to this topic.
 * @param db - dbtree
 * @param topic - topic
 * @param ret_msg - dbtree_retain_msg
 * @return
 */
void *dbtree_insert_retain(
    dbtree *db, char *topic, dbtree_retain_msg *ret_msg);

/**
 * @brief dbtree_delete_retain - Delete all retain message to this topic.
 * @param db - dbtree
 * @param topic - topic
 * @return ctxt or NULL, if client can be delete or not
 */
void *dbtree_delete_retain(dbtree *db, char *topic);

/**
 * @brief dbtree_find_retain - Get all retain message to this topic.
 * @param db - dbtree
 * @param topic - topic
 * @return dbtree_retain_msg pointer vector
 */
dbtree_retain_msg **dbtree_find_retain(dbtree *db, char *topic);

/**
 * @brief dbtree_find_shared_clients - This function
 * will Find shared subscribe client.
 * @param dbtree - dbtree
 * @param topic - topic
 * @return pipe id array
 */
uint32_t *
dbtree_find_shared_clients(dbtree *db, char *topic);

/**
 * @brief dbtree_get_tree - This function will
 * get all info about this tree.
 * @param dbtree - dbtree
 * @param cb - a callback function
 * @return all info about this tree
 */
void ***dbtree_get_tree(dbtree *db, void *(*cb)(uint32_t pipe_id));

#endif
