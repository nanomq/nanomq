#ifndef MQTT_DB_H
#define MQTT_DB_H

#include "cvector.h"
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

typedef struct {
	uint32_t session_id;
	uint32_t pipe_id;
	void *   ctxt;
} dbtree_client;

typedef struct {
	uint8_t qos;
	bool    exist;
	char *  m;
	void *  message;
} dbtree_retain_msg;

typedef struct {
	uint32_t session_id;
	void *   ctxt;
} dbtree_session;

typedef struct dbtree_node dbtree_node;

struct dbtree_node {
	char *             topic;
	int                plus;
	int                well;
	dbtree_retain_msg *retain;
	cvector(dbtree_client *) clients;
	cvector(dbtree_node *) child;
	cvector(dbtree_session *) session_vector;
	pthread_rwlock_t rwlock;
};

typedef struct {
	uint32_t session_id;
	cvector(void *) msg_list;
} dbtree_session_msg;

typedef struct {
	dbtree_node *root;
	cvector(dbtree_session_msg *) session_msg_list;
	pthread_rwlock_t rwlock;
	pthread_rwlock_t rwlock_session;
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
	char *       y     = (char *) y_;
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
	uint32_t *     pipe_id = (uint32_t *) y_;
	dbtree_client *ele_x   = (dbtree_client *) x_;
	return *pipe_id - ele_x->pipe_id;
}

//TODO 
/**
 * @brief ids_cmp - A callback to compare different id
 * @param x - normally x is pointer of id
 * @param y - normally y is pointer of id
 * @return 0, minus or plus, based on strcmp
 */
static inline int
ids_cmp(void *x_, void *y_)
{
	uint32_t *     pipe_id = (uint32_t *) y_;
	uint32_t *id   = (uint32_t *) x_;
	return *pipe_id - *id;
}

static inline int
session_msg_cmp(void *x_, void *y_)
{
	uint32_t *          y     = (uint32_t *) y_;
	dbtree_session_msg *ele_x = (dbtree_session_msg *) x_;
	return *y - ele_x->session_id;
}

static inline int
session_cmp(void *x_, void *y_)
{
	uint32_t *      y     = (uint32_t *) y_;
	dbtree_session *ele_x = (dbtree_session *) x_;
	return *y - ele_x->session_id;
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
 * topic and client id is exist on the tree, if
 * there is not exist, this func will insert node
 * recursively until find all topic then insert
 * client on the node.
 * @param dbtree - dbtree_node
 * @param topic - topic
 * @param ctxt - data related with pipe_id
 * @param pipe_id - pipe id
 * @return
 */
void *dbtree_insert_client(
    dbtree *db, char *topic, void *ctxt, uint32_t pipe_id);

/**
 * @brief dbtree_restore_session - This function
 * will be called when connection is established
 * and cleansession = 0. Before call this function,
 * should check table that have relationship client
 * identify and topic queue. Then use topic and pipe
 * identify to get the session, delete it from session
 * list and add to client vector.
 * @param dbtree - dbtree
 * @param topic - topic
 * @param session_id - client id hash value
 * @param pipe_id - pipe id
 * @return
 */
void *dbtree_restore_session(
    dbtree *db, char *topic, uint32_t session_id, uint32_t pipe_id);

/**
 * @brief dbtree_cache_session - This function will
 * be called when disconnection and cleansession = 0.
 * Then use topic and pipe identify to get the client,
 * delete it from client vector and add to session list.
 * @param dbtree - dbtree
 * @param topic - topic
 * @param session_id - client id hash value
 * @param pipe_id - pipe id
 * @return
 */
void *dbtree_cache_session(
    dbtree *db, char *topic, uint32_t session_id, uint32_t pipe_id);

/**
 * @brief dbtree_delete_session - This function will
 * be called when connection is established and
 * cleansession change from 0 to 1. Then use topic
 * and pipe identify to get the client, delete it
 * from session list.
 * @param dbtree - dbtree
 * @param topic - topic
 * @param session_id - client id hash value
 * @param pipe_id - pipe id
 * @return
 */
void *dbtree_delete_session(
    dbtree *db, char *topic, uint32_t session_id, uint32_t pipe_id);

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
 * @brief dbtree_cache_session_msg - This function will
 * be called when cleansession = 0 and qos 1,2 message 
 * is sent but not receive ack. cache message to dbtree.
 * @param dbtree - dbtree
 * @param topic - topic
 * @param client - client
 * @return ctxt or NULL, if client can be delete or not
 */
int dbtree_cache_session_msg(dbtree *db, void *msg, uint32_t session_id);

/**
 * @brief dbtree_find_clients_and_cache_msg - Get all 
 * subscribers online to this topic and cache session 
 * message for offline.
 * @param dbtree - dbtree
 * @param topic - topic
 * @param msg_cnt - message used count
 * @return dbtree_client
 */
void **dbtree_find_clients_and_cache_msg(dbtree *db, char *topic, void *msg, size_t *msg_cnt);

/**
 * @brief dbtree_restore_session_msg - Get all be 
 * cached session message.
 * message for offline.
 * @param dbtree - dbtree
 * @param topic - topic
 * @return dbtree_client
 */
void **dbtree_restore_session_msg(dbtree *db, uint32_t session_id);

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
 * @param msg_cnt - message used count
 * @return dbtree_client
 */
void **dbtree_find_shared_sub_clients(dbtree *db, char *topic, void *msg, size_t *msg_cnt);


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
 * @return
 */
void *dbtree_insert_shared_sub_client(
    dbtree *db, char *topic, void *ctxt, uint32_t pipe_id);

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


#endif
