#ifndef MQTT_DB_H
#define MQTT_DB_H

#include "cvector.h"
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdatomic.h>

typedef enum {
	MQTT_VERSION_V311 = 4,
	MQTT_VERSION_V5   = 5,
} mqtt_version_t;

typedef struct {
	int              ref;
	void            *ctx;
	pthread_rwlock_t rwlock;
} dbtree_ctxt;

typedef struct {
	uint32_t       session_id;
	uint32_t       pipe_id;
	void          *ctxt;
	mqtt_version_t ver;
} dbtree_client;

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
	cvector(dbtree_client *) clients;
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

/**
 * @brief client_cmp - A callback to compare different client
 * @param x - normally x is pointer of dbtree_client
 * @param y - normally y is pointer of id
 * @return 0, minus or plus, based on strcmp
 */
static inline int
client_cmp(void *x_, void *y_)
{
	uint32_t      *pipe_id = (uint32_t *) y_;
	dbtree_client *ele_x   = (dbtree_client *) x_;
	return *pipe_id - ele_x->pipe_id;
}

// TODO
/**
 * @brief ids_cmp - A callback to compare different id
 * @param x - normally x is pointer of id
 * @param y - normally y is pointer of id
 * @return 0, minus or plus, based on strcmp
 */
static inline int
ids_cmp(void *x_, void *y_)
{
	uint32_t *pipe_id = (uint32_t *) y_;
	uint32_t *id      = (uint32_t *) x_;
	return *pipe_id - *id;
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
 * @param ctxt - data related with pipe_id
 * @param pipe_id - pipe id
 * @param mqtt_version_t - mqtt protocol version
 * @return
 */
void *dbtree_insert_client(
    dbtree *db, char *topic, void *ctxt, uint32_t pipe_id, mqtt_version_t ver);

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
void *dbtree_find_client(dbtree *db, char *topic, uint32_t pipe_id);

/**
 * @brief dbtree_delete_client - This function will
 * be called when disconnection and cleansession = 1.
 * check if this topic and client id is exist on the
 * tree, if there is exist, this func will delete
 * related node and client on the tree
 * @param dbtree - dbtree
 * @param topic - topic
 * @param client - client
 * @return ctxt or NULL, if client can be delete or not
 */
void *dbtree_delete_client(
    dbtree *db, char *topic, uint32_t session_id, uint32_t pipe_id);

/**
 * @brief dbtree_find_clients_and_cache_msg - Get all
 * subscribers online to this topic
 * @param dbtree - dbtree
 * @param topic - topic
 * @return dbtree_client
 */
void **dbtree_find_clients(dbtree *db, char *topic);

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
 * @brief dbtree_find_shared_sub_clients - This function
 * will Find shared subscribe client.
 * @param dbtree - dbtree
 * @param topic - topic
 * @return dbtree_client
 */
void **dbtree_find_shared_sub_clients(dbtree *db, char *topic);

/**
 * @brief dbtree_check_shared_sub - Check if
 * a topic is a shared topic.
 * @param topic - topic
 * @return
 */
bool dbtree_check_shared_sub(const char *topic);

/**
 * @brief dbtree_insert_shared_subscribe_client - Insert
 * shared subscribe client to dbtree.
 * @param dbtree - dbtree_node
 * @param topic - topic
 * @param ctxt - data related with pipe_id
 * @param pipe_id - pipe id
 * @param mqtt_version_t - mqtt protocol version
 * @return
 */
void *dbtree_insert_shared_sub_client(
    dbtree *db, char *topic, void *ctxt, uint32_t pipe_id, mqtt_version_t ver);

/**
 * @brief dbtree_delete_shared_subscibe_client - This function will
 * delete a client, when unsubscribe is called.
 * @param dbtree - dbtree
 * @param topic - topic
 * @param client - client
 * @return ctxt or NULL, if client can be delete or not
 */
void *dbtree_delete_shared_sub_client(
    dbtree *db, char *topic, uint32_t session_id, uint32_t pipe_id);

dbtree_ctxt *dbtree_ctxt_new(void *ctx);

void *dbtree_ctxt_delete(dbtree_ctxt *ctxt);

void dbtree_ctxt_clone(dbtree_ctxt *ctxt);

int dbtree_ctxt_free(dbtree_ctxt *ctxt);

int dbtree_ctxt_get_ref(dbtree_ctxt *ctxt);

void ***dbtree_get_tree(dbtree *db, void *(*cb)(void *ctxt));

#endif
