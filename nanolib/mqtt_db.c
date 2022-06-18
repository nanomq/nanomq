//
// Copyright 2020 NanoMQ Team, Inc. <jaylin@emqx.io> //
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <limits.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>


#include "include/binary_search.h"
#include "include/cvector.h"
#include "include/dbg.h"
#include "include/hash_table.h"
#include "include/mqtt_db.h"
#include "include/zmalloc.h"

#define ROUND_ROBIN
// #define RANDOM

static int acnt = 0;

pthread_rwlock_t rwlock = PTHREAD_RWLOCK_INITIALIZER;

dbtree_ctxt *
dbtree_ctxt_new(void *ctx)
{
	dbtree_ctxt *ctxt = (dbtree_ctxt *) zmalloc(sizeof(dbtree_ctxt));
	if (ctxt == NULL) {
		log_err("Memory alloc error!");
		return NULL;
	}
	ctxt->ref         = 1;
	ctxt->ctx         = ctx;
	return ctxt;
}

void *
dbtree_ctxt_delete(dbtree_ctxt *ctxt)
{
	void *ctx = NULL;
	pthread_rwlock_wrlock(&(rwlock));
	assert(ctxt != NULL && ctxt->ref == 0);
	ctx = ctxt->ctx;
	zfree(ctxt);
	ctxt = NULL;
	pthread_rwlock_unlock(&(rwlock));
	return ctx;
}

int
dbtree_ctxt_free(dbtree_ctxt *ctxt)
{
	pthread_rwlock_wrlock(&(rwlock));
	assert(ctxt != NULL && ctxt->ref > 0);
	int ref = (--ctxt->ref);
	pthread_rwlock_unlock(&(rwlock));
	return ref;
}

int dbtree_ctxt_get_ref(dbtree_ctxt *ctxt)
{
	assert(ctxt != NULL);
	pthread_rwlock_rdlock(&(rwlock));
	int ref = ctxt->ref;
	pthread_rwlock_unlock(&(rwlock));
	return ref;
}

void 
dbtree_ctxt_clone(dbtree_ctxt *ctxt)
{
	pthread_rwlock_wrlock(&(rwlock));
	assert(ctxt != NULL && ctxt->ref > 0);
	if (ctxt) {
		if (ctxt->ref > 0) {
			ctxt->ref++;
		} else {
			log_err("Error clone ctxt->ref == %d", ctxt->ref);
		}
	}
	pthread_rwlock_unlock(&(rwlock));
}

/**
 * @brief print_client - A way to print client in vec.
 * @param v - normally v is an dynamic array
 * @return void
 */
static void
print_client(dbtree_client **v)
{
#ifdef NOLOG
#else
	puts("____________PRINT_DB_CLIENT___________");
	if (v) {
		for (int i = 0; i < cvector_size(v); i++) {
			printf("%d\t", v[i]->pipe_id);
		}
		puts("");
	}
	puts("____________PRINT_DB_CLIENT___________");
#endif
}

/**
 * @brief topic_count - Count how many levels.
 * @param topic - original topic
 * @return topic level
 */
static int
topic_count(char *topic)
{
	int   cnt = 0;
	char *t   = topic;

	while (t) {
		// log_info("%s", t);
		t = strchr(t, '/');
		cnt++;
		if (t == NULL) {
			break;
		}
		t++;
	}

	return cnt;
}

/**
 * @brief topic_parse - Parsing topic to topic queue.
 * @param topic - original topic
 * @return topic queue
 */
static char **
topic_parse(char *topic)
{
	if (topic == NULL) {
		log_err("topic is NULL");
		return NULL;
	}

	int   row   = 0;
	int   len   = 2;
	char *b_pos = topic;
	char *pos   = NULL;

	int cnt = topic_count(topic);

	// Here we will get (cnt + 1) memory, one for NULL end
	char **topic_queue = (char **) zmalloc(sizeof(char *) * (cnt + 1));

	while ((pos = strchr(b_pos, '/')) != NULL) {

		len              = pos - b_pos + 1;
		topic_queue[row] = (char *) zmalloc(sizeof(char) * len);
		memcpy(topic_queue[row], b_pos, (len - 1));
		topic_queue[row][len - 1] = '\0';
		b_pos                     = pos + 1;
		row++;
	}

	len = strlen(b_pos);

	topic_queue[row] = (char *) zmalloc(sizeof(char) * (len + 1));
	memcpy(topic_queue[row], b_pos, (len));
	topic_queue[row][len] = '\0';
	topic_queue[++row]    = NULL;

	return topic_queue;
}

/**
 * @brief topic_queue_free - Free topic queue memory.
 * @param topic_queue - topic array
 * @return void
 */

static void
topic_queue_free(char **topic_queue)
{
	char * t  = NULL;
	char **tt = topic_queue;

	while (*topic_queue) {
		t = *topic_queue;
		topic_queue++;
		zfree(t);
		t = NULL;
	}

	if (tt) {
		zfree(tt);
	}
}

void ***
dbtree_get_tree(dbtree *db, void *(*cb)(void *ctxt))
{
	if (db == NULL) {
		return NULL;
	}

	pthread_rwlock_wrlock(&(db->rwlock));

	dbtree_node *node = db->root;
	dbtree_node **nodes = NULL;
	dbtree_node **nodes_t = NULL;
	dbtree_info ***ret = NULL;

	cvector_push_back(nodes, node);
	while (!cvector_empty(nodes)) {
		dbtree_info **ret_line_ping = NULL;
		for (int i = 0; i < cvector_size(nodes); i++) {
		dbtree_info *vn = zmalloc(sizeof(dbtree_info));
			vn->clients = NULL;
			if (cb) {
				for (int j = 0; j < cvector_size(nodes[i]->clients); j++) {
					void *val = cb(nodes[i]->clients[j]->ctxt);
					if (val) {
						cvector_push_back(vn->clients, val);
					}
				}

			}
	
			cvector_push_back(ret_line_ping, vn);

			vn->topic = zstrdup(nodes[i]->topic);
			vn->cld_cnt = cvector_size(nodes[i]->child);
			for (int j = 0; j < vn->cld_cnt; j++) {
				cvector_push_back(
				    nodes_t, (nodes[i]->child)[j]);
			}
		}
		cvector_push_back(ret, ret_line_ping);
		cvector_free(nodes);
		nodes = NULL;

		dbtree_info **ret_line_pang = NULL;
		for (int i = 0; i < cvector_size(nodes_t); i++) {
			dbtree_info *vn = zmalloc(sizeof(dbtree_info));
			vn->clients = NULL;
			if (cb) {
				for (int j = 0; j < cvector_size(nodes_t[i]->clients); j++) {
					void *val = cb(nodes_t[i]->clients[j]->ctxt);
					if (val) {
						cvector_push_back(vn->clients, val);
					}
				}

			}

			cvector_push_back(ret_line_pang, vn);

			vn->topic = zstrdup(nodes_t[i]->topic);
			vn->cld_cnt = cvector_size(nodes_t[i]->child);
			for (int j = 0; j < vn->cld_cnt; j++) {
				cvector_push_back(
				    nodes, (nodes_t[i]->child)[j]);
			}
		}
		cvector_push_back(ret, ret_line_pang);
		cvector_free(nodes_t);
		nodes_t = NULL;
	}
	pthread_rwlock_unlock(&(db->rwlock));
	return (void***) ret;
}


/**
 * @brief dbtree_print - Print dbtree for debug.
 * @param dbtree - dbtree
 * @return void
 */
#ifdef NOLOG
void
dbtree_print(dbtree *db)
{
	return;
}
#else
void
dbtree_print(dbtree *db)
{
	if (db == NULL) {
		return;
	}

	pthread_rwlock_wrlock(&(db->rwlock));

	dbtree_node *node = db->root;
	dbtree_node **nodes = NULL;
	dbtree_node **nodes_t = NULL;

	const char node_fmt[] = "[%-5s]\t";
	cvector_push_back(nodes, node);
	puts("___________PRINT_DB_TREE__________");
	while (!cvector_empty(nodes)) {
		for (int i = 0; i < cvector_size(nodes); i++) {
			printf(node_fmt, nodes[i]->topic);

			for (int j = 0; j < cvector_size(nodes[i]->child);
			     j++) {
				cvector_push_back(
				    nodes_t, (nodes[i]->child)[j]);
			}
		}
		printf("\n");
		cvector_free(nodes);
		nodes = NULL;

		for (int i = 0; i < cvector_size(nodes_t); i++) {
			printf(node_fmt, nodes_t[i]->topic);

			for (int j = 0; j < cvector_size(nodes_t[i]->child);
			     j++) {
				cvector_push_back(
				    nodes, (nodes_t[i]->child)[j]);
			}
		}
		printf("\n");
		cvector_free(nodes_t);
		nodes_t = NULL;
	}
	pthread_rwlock_unlock(&(db->rwlock));
	puts("___________PRINT_DB_TREE__________");
}
#endif

/**
 * @brief skip_wildcard - To get left boundry of binary search
 * @param node - dbtree_node
 * @return l - left boundry
 */
static int
skip_wildcard(dbtree_node *node)
{
	int l = 0;
	if (node->plus != -1) {
		l++;
	}
	if (node->well != -1) {
		l++;
	}

	return l;
}

/**
 * @brief find_next - check if this topic is exist in this level.
 * @param node - dbtree_node
 * @param equal - a return state value
 * @param topic_queue - topic queue
 * @param index - search index will be return
 * @return dbtree_node we find or original node
 */
// TODO topic or topic queue
// TODO return NULL if no find ?
static dbtree_node *
find_next(dbtree_node *node, bool *equal, char **topic_queue, int *index)
{
	if (node == NULL || node->child == NULL) {
		return NULL;
	}

	cvector(dbtree_node *) t = node->child;

	int l = skip_wildcard(node);

	if (true ==
	    binary_search((void **) t, l, index, *topic_queue, node_cmp)) {
		*equal = true;
		return t[*index];
	}

	return node;
}

/**
 * @brief dbtree_client_new - create a client
 * @param id - client id
 * @param ctxt - client ctxt
 * @return dbtree_client*
 */
static dbtree_client *
dbtree_client_new(uint32_t id, void *ctxt, uint32_t pipe_id, mqtt_version_t ver)
{
	dbtree_client *client = NULL;
	client = (dbtree_client *) zmalloc(sizeof(dbtree_client));
	if (client == NULL) {
		return NULL;
	}

	log_info("New client pipe_id: [%d], session id: [%d]", pipe_id, id);
	client->session_id = id;
	client->pipe_id    = pipe_id;
	client->ctxt       = (void *) dbtree_ctxt_new(ctxt);
	client->ver        = ver;
	return client;
}

/**
 * @brief dbtree_client_free - free a client memory
 * @param id - client id
 * @return dbtree_client*
 */
static void *
dbtree_client_free(dbtree_client *client)
{
	void *ctxt = NULL;
	log_info("Delete client pipe_id: [%d]", client->pipe_id);
	if (client) {
		if (client->ctxt) {
			ctxt         = client->ctxt;
			client->ctxt = NULL;
		}

		zfree(client);
		client = NULL;
	}

	return ctxt;
}

/**
 * @brief dbtree_node_new - create a node
 * @param topic - topic
 * @return dbtree_node*
 */
static dbtree_node *
dbtree_node_new(char *topic)
{
	dbtree_node *node = NULL;
	node              = (dbtree_node *) zmalloc(sizeof(dbtree_node));
	if (node == NULL) {
		return NULL;
	}
	node->topic = zstrdup(topic);
	log_info("New node: [%s]", node->topic);

	node->retain  = NULL;
	node->child   = NULL;
	node->clients = NULL;
	node->well    = -1;
	node->plus    = -1;

	pthread_rwlock_init(&(node->rwlock), NULL);
	return node;
}

/**
 * @brief dbtree_node_free - Free a node memory
 * @param node - dbtree_node *
 * @return void
 */
static void
dbtree_node_free(dbtree_node *node)
{
	if (node) {
		if (node->topic) {
			log_info("Delete node: [%s]", node->topic);
			zfree(node->topic);
			node->topic = NULL;
		}
		pthread_rwlock_destroy(&(node->rwlock));
		zfree(node);
		node = NULL;
	}
}

/**
 * @brief dbtree_create - Create a dbtree, declare a global variable as func
 * para
 * @param dbtree - dbtree
 * @return void
 */
void
dbtree_create(dbtree **db)
{
	*db = (dbtree *) zmalloc(sizeof(dbtree));
	memset(*db, 0, sizeof(dbtree));

	dbtree_node *node       = dbtree_node_new("\0");
	(*db)->root             = node;
	pthread_rwlock_init(&((*db)->rwlock), NULL);
#ifdef RANDOM
	srand(time(NULL));
#endif
	return;
}

/**
 * @brief dbtree_destory - Destory dbtree tree
 * @param dbtree - dbtree
 * @return void
 */
void
dbtree_destory(dbtree *db)
{
	if (db) {
		dbtree_node_free(db->root);
		zfree(db);
		db = NULL;
	}

	// pthread_rwlock_destroy(&(db->rwlock));
	// pthread_rwlock_destroy(&(db->rwlock_session));
}

/**
 * @brief find_client_cb - find client
 * @param node - dbtree_node
 * @param args - user ctxt
 * @return
 */
static void *
find_client_cb(dbtree_node *node, void *args)
{
	pthread_rwlock_rdlock(&(node->rwlock));

	int       index   = 0;
	uint32_t *pipe_id = (uint32_t *) args;
	dbtree_ctxt *    ctxt    = NULL;

	if (true ==
	    binary_search(
	        (void **) node->clients, 0, &index, pipe_id, client_cmp)) {
		ctxt = (dbtree_ctxt*) node->clients[index]->ctxt;
		// if ref == 0, implict that it will de deleted.
		if (0 == dbtree_ctxt_get_ref(ctxt)) {
			ctxt = NULL;
		} else {
			dbtree_ctxt_clone(ctxt);
		}
	}

	pthread_rwlock_unlock(&(node->rwlock));
	return ctxt;
}

/**
 * @brief insert_client_cb - insert a client on the right position
 * @param node - dbtree_node
 * @param args - client
 * @return
 */
static void *
insert_client_cb(dbtree_node *node, void *args)
{
	pthread_rwlock_wrlock(&(node->rwlock));

	int            index  = 0;
	dbtree_client *client = (dbtree_client *) args;

	if (false ==
	    binary_search((void **) node->clients, 0, &index,
	        &(client->pipe_id), client_cmp)) {
		if (index == cvector_size(node->clients)) {
			cvector_push_back(node->clients, client);
		} else {
			cvector_insert(node->clients, index, client);
		}
	} else {
		// TODO lazy binding
		dbtree_client_free(client);
	}

	pthread_rwlock_unlock(&(node->rwlock));
	return NULL;
}

/**
 * @brief is_plus - Determine if the current topic is "#"
 * @param topic_data - topic in one level
 * @return true, if curr topic is "#"
 */
static bool
is_well(char *topic_data)
{
	if (topic_data == NULL) {
		return false;
	}
	return !strcmp(topic_data, "#");
}

/**
 * @brief is_plus - Determine if the current topic is "+"
 * @param topic_data - topic in one level
 * @return true, if curr topic is "+"
 */
static bool
is_plus(char *topic_data)
{
	// TODO
	if (topic_data == NULL) {
		return false;
	}
	return !strcmp(topic_data, "+");
}

/**
 * @brief dbtree_node_insert - insert node until topic_queue is NULL
 * @param node - dbtree_node
 * @param topic_queue - topic queue position
 * @param client - client info
 * @return void
 */
static dbtree_node *
dbtree_node_insert(dbtree_node *node, char **topic_queue)
{
	if (node == NULL || topic_queue == NULL) {
		log_err("node or topic_queue is NULL");
		return NULL;
	}

	while (*topic_queue) {
		dbtree_node *new_node = NULL;
		if (is_well(*topic_queue)) {
			if (node->well != -1) {
				new_node = node->child[node->well];
			} else {
				if (node->plus == 0) {
					node->plus = 1;
				}

				node->well = 0;
				new_node   = dbtree_node_new(*topic_queue);
				cvector_insert(
				    node->child, node->well, new_node);
			}

		} else if (is_plus(*topic_queue)) {
			if (node->plus != -1) {
				new_node = node->child[node->plus];
			} else {
				if (node->well == 0) {
					node->well = 1;
				}

				node->plus = 0;
				new_node   = dbtree_node_new(*topic_queue);
				cvector_insert(
				    node->child, node->plus, new_node);
			}
		} else {
			int l = skip_wildcard(node);
			if (l == cvector_size(node->child)) {
				new_node = dbtree_node_new(*topic_queue);
				cvector_push_back(node->child, new_node);

			} else {
				int index = 0;
				if (false ==
				    binary_search((void **) node->child, l,
				        &index, *topic_queue, node_cmp)) {
					new_node =
					    dbtree_node_new(*topic_queue);

					//  TODO
					if (index ==
					    cvector_size(node->child)) {
						cvector_push_back(
						    node->child, new_node);
					} else {
						cvector_insert(node->child,
						    index, new_node);
					}
				} else {
					new_node = node->child[index];
				}
			}
		}

		topic_queue++;
		node = new_node;
	}

	return node;
}

/**
 * @brief search_insert_node - check if this
 * topic and client id is exist on the tree, if
 * there is not exist, this func will insert
 * related node and client on the tree
 * @param dbtree - dbtree_node
 * @param topic - topic
 * @param client - client
 * @return
 */
static void *
search_insert_node(dbtree *db, char *topic, void *args,
    void *(*inserter)(dbtree_node *node, void *args))
{
	if (db == NULL || topic == NULL) {
		log_err("db or topic is NULL");
		return NULL;
	}

	char **topic_queue = topic_parse(topic);
	char **for_free    = topic_queue;

	pthread_rwlock_wrlock(&(db->rwlock));
	dbtree_node *node = db->root;
	// while dbtree is NULL, we will insert directly.

	if (!(node->child && *node->child)) {
		node = dbtree_node_insert(node, topic_queue);
	} else {

		while (*topic_queue && node->child && *node->child) {
			dbtree_node *node_t = *node->child;
			log_info("topic is: %s, node->topic is: %s",
			    *topic_queue, node_t->topic);
			if (strcmp(node_t->topic, *topic_queue)) {
				bool equal = false;
				int  index = 0;

				node_t = find_next(
				    node, &equal, topic_queue, &index);
				if (equal == false) {
					/*
					 ** If no node is matched with topic
					 ** insert node until topic_queue
					 ** is NULL
					 */
					log_info("searching unequal");
					node = dbtree_node_insert(
					    node_t, topic_queue);
					break;
				}
			}

			if (node_t->child && *node_t->child &&
			    *(topic_queue + 1)) {
				topic_queue++;
				node = node_t;
			} else if (*(topic_queue + 1) == NULL) {
				log_info("Search and insert client");
				node = node_t;
				break;
			} else {
				log_info("Insert node and client");
				node = dbtree_node_insert(
				    node_t, topic_queue + 1);
				break;
			}
		}
	}

	void *ret = inserter(node, args);
	pthread_rwlock_unlock(&(db->rwlock));
	topic_queue_free(for_free);
	return ret;
}

void *
dbtree_insert_client(dbtree *db, char *topic, void *ctxt, uint32_t pipe_id, mqtt_version_t ver)
{
	dbtree_client *client = dbtree_client_new(0, ctxt, pipe_id, ver);
	return search_insert_node(db, topic, client, insert_client_cb);
}

void *
dbtree_find_client(dbtree *db, char *topic, uint32_t pipe_id)
{
	return search_insert_node(db, topic, &pipe_id, find_client_cb);
}

typedef dbtree_client *dbtree_client_ptr;
typedef dbtree_node *  dbtree_node_ptr;

/**
 * @brief collect_clients - Get all clients in nodes
 * @param vec - all clients obey this rule will insert
 * @param nodes - all node need to be compare
 * @param nodes_t - all node need to be compare next time
 * @param topic_queue - topic queue position
 * @return all clients on lots of nodes
 */
static dbtree_client ***
collect_clients(dbtree_client ***vec,
    dbtree_node **nodes, dbtree_node ***nodes_t, char **topic_queue)
{
	// TODO insert sort for clients and session_vectors
	while (!cvector_empty(nodes)) {
		dbtree_node **node_t_ = cvector_end(nodes) - 1;
		dbtree_node * node_t  = *node_t_;
		cvector_pop_back(nodes);

		if (node_t == NULL || node_t->child == NULL ||
		    (*(node_t->child)) == NULL) {
			continue;
		}

		dbtree_node * t     = *node_t->child;
		dbtree_node **child = node_t->child;

		if (node_t->well != -1) {
			if (!cvector_empty(child[node_t->well]->clients)) {
				log_info("Find # tag");
				cvector_push_back(
				    vec, child[node_t->well]->clients);
			}

		}

		if (node_t->plus != -1) {
			if (*(topic_queue + 1) == NULL) {
				log_info("add + clients");
				if (!cvector_empty(
				        child[node_t->plus]->clients)) {
					cvector_push_back(
					    vec, child[node_t->plus]->clients);
				}

			} else {
				cvector_push_back(
				    (*nodes_t), child[node_t->plus]);
				log_info("add node_t: %s",
				    (*(cvector_end((*nodes_t)) - 1))->topic);
			}
		}

		bool equal = false;
		if (strcmp(t->topic, *topic_queue)) {
			int index = 0;
			t = find_next(node_t, &equal, topic_queue, &index);
		} else {
			equal = true;
		}

		if (equal == true) {
			log_info("Searching client: %s", t->topic);
			if (*(topic_queue + 1) == NULL) {
				if (!cvector_empty(t->clients)) {
					log_info(
					    "Searching client: %s", t->topic);
					cvector_push_back(vec, t->clients);
				}

				if (t->well != -1) {
					t = t->child[t->well];
					if (!cvector_empty(t->clients)) {
						log_info(
						    "Searching client: %s",
						    t->topic);
						cvector_push_back(
						    vec, t->clients);
					}
				}

			} else {
				log_info("Searching client: %s", t->topic);
				cvector_push_back((*nodes_t), t);
				log_info("add node_t: %s",
				    (*(cvector_end((*nodes_t)) - 1))->topic);
			}
		}
	}

	return vec;
}

/**
 * @brief iterate_client - Deduplication for all clients
 * @param v - client
 * @return dbtree_client
 */
static void **
iterate_client(dbtree_client ***v)
{
	cvector(void *) ctxts   = NULL;
	cvector(uint32_t *) ids = NULL;

	if (v) {
		for (int i = 0; i < cvector_size(v); ++i) {

			for (int j = 0; j < cvector_size(v[i]); j++) {
				int index = 0;
				dbtree_ctxt *ctxt = (dbtree_ctxt *) v[i][j]->ctxt;
				if (v[i][j]->ver == MQTT_VERSION_V311) {
					// if ref == 0, implict that it will de deleted.
					if (0 != dbtree_ctxt_get_ref(ctxt)) {
						dbtree_ctxt_clone(ctxt);
						cvector_push_back(ctxts, (void*) ctxt);
					}
					continue;
				}

				if (false ==
				    binary_search((void **) ids, 0, &index,
				        &v[i][j]->pipe_id, ids_cmp)) {
					if (cvector_empty(ids) ||
					    index == cvector_size(ids)) {
						cvector_push_back(
						    ids, &v[i][j]->pipe_id);
					} else {
						cvector_insert(ids, index,
						    &v[i][j]->pipe_id);
					}

					if (0 != dbtree_ctxt_get_ref(ctxt)) {
						dbtree_ctxt_clone(ctxt);
						cvector_push_back(ctxts, (void*) ctxt);
					}
				}
			}
		}
		cvector_free(ids);
	}

	return (void **) ctxts;
}

void **
search_client(dbtree *db, char *topic)
{
	if (db == NULL || topic == NULL) {
		log_err("db or topic is NULL");
		return NULL;
	}

	char **topic_queue = topic_parse(topic);
	char **for_free    = topic_queue;
	void **ret         = NULL;

	pthread_rwlock_rdlock(&(db->rwlock));

	dbtree_node *node                              = db->root;
	cvector(dbtree_client **) ctxts                = NULL;
	cvector(dbtree_node *) nodes                   = NULL;
	cvector(dbtree_node *) nodes_t                 = NULL;

	if (node->child && *node->child) {
		cvector_push_back(nodes, node);
	}

	// log_info("node->topic %s, topic_queue %s", node->topic,
	// *topic_queue); printf("node->topic %s, topic_queue %s\n",
	// node->topic, *topic_queue);

	while (*topic_queue && (!cvector_empty(nodes))) {

		ctxts = collect_clients(ctxts, nodes,
		    &nodes_t, topic_queue);
		topic_queue++;
		if (*topic_queue == NULL) {
			break;
		}
		ctxts = collect_clients(ctxts, nodes_t,
		    &nodes, topic_queue);
		topic_queue++;
	}

	ret = iterate_client(ctxts);

	pthread_rwlock_unlock(&(db->rwlock));
	topic_queue_free(for_free);
	cvector_free(nodes);
	cvector_free(nodes_t);
	cvector_free(ctxts);

	return ret;
}

void **
dbtree_find_clients(dbtree *db, char *topic)
{
	return search_client(db, topic);
}

/**
 * @brief delete_dbtree_client - delete dbtree client
 * @param node - dbtree_node
 * @param id - client id
 * @param pipe_id - pipe id
 * @return
 */
static void *
delete_dbtree_client(dbtree_node *node, uint32_t pipe_id)
{
	int   index = 0;
	void *ctxt  = NULL;

	pthread_rwlock_wrlock(&(node->rwlock));
	// TODO maybe ctxt need to be protected
	print_client(node->clients);
	if (true ==
	    binary_search(
	        (void **) node->clients, 0, &index, &pipe_id, client_cmp)) {
		dbtree_client *c = node->clients[index];
		cvector_erase(node->clients, index);
		print_client(node->clients);
		ctxt = dbtree_client_free(c);

		if (cvector_empty(node->clients)) {
			cvector_free(node->clients);
			node->clients = NULL;
		} else {
			print_client(node->clients);
		}
	} else {
		log_err("Not find pipe id: [%d]", pipe_id);
		log_err("node->topic: %s", node->topic);
		for (int i = 0; i < cvector_size(node->clients); i++) {
			log_err("node->clients[%d]: [%d]:", i,
			    node->clients[i]->pipe_id);
		}
	}

	pthread_rwlock_unlock(&(node->rwlock));
	return ctxt;
}

/**
 * @brief delete_dbtree_node - delete dbtree node
 * @param dbtree - dbtree_node
 * @param index - index
 * @return
 */
static int
delete_dbtree_node(dbtree_node *node, int index)
{
	pthread_rwlock_wrlock(&(node->rwlock));
	dbtree_node *node_t = node->child[index];
	// TODO plus && well

	if (cvector_empty(node_t->child) && cvector_empty(node_t->clients)) {
		log_info("Delete node: [%s]", node_t->topic);
		cvector_free(node_t->child);
		cvector_free(node_t->clients);
		zfree(node_t->topic);
		cvector_erase(node->child, index);
		zfree(node_t);
		node_t = NULL;
		if (index == 0) {
			if (node->plus >= 0) {
				node->plus--;
			}

			if (node->well >= 0) {
				node->well--;
			}
		}

		if (index == 1) {
			if (node->plus == 1) {
				node->plus = -1;
			}

			if (node->well == 1) {
				node->well = -1;
			}
		}
	}

	if (cvector_empty(node->child)) {
		cvector_free(node->child);
		node->child = NULL;
	}

	pthread_rwlock_unlock(&(node->rwlock));
	return 0;
}

void *
search_and_delete(dbtree *db, char *topic, uint32_t session_id,
    uint32_t pipe_id)
{
	if (db == NULL || topic == NULL) {
		log_err("db or topic is NULL");
		return NULL;
	}
	pthread_rwlock_wrlock(&(db->rwlock));

	char **       topic_queue = topic_parse(topic);
	char **       for_free    = topic_queue;
	dbtree_node * node        = db->root;
	dbtree_node **node_buf    = NULL;
	void *        ctxt        = NULL;
	int *         vec         = NULL;
	int           index       = 0;

	while (*topic_queue && node->child && *node->child) {
		index               = 0;
		dbtree_node *node_t = *node->child;
		log_info("topic is: %s, node->topic is: %s", *topic_queue,
		    node_t->topic);
		if (strcmp(node_t->topic, *topic_queue)) {
			bool equal = false;
			if (is_well(*topic_queue) && (node->well != -1)) {
				index = node->well;
				equal = true;
			}

			if (is_plus(*topic_queue) && (node->plus != -1)) {
				index = node->plus;
				equal = true;
			}

			node_t = node->child[index];

			if (equal == false) {
				// TODO node_t or node->child[index], to
				// determine if node_t is needed
				node_t = find_next(
				    node, &equal, topic_queue, &index);
				if (equal == false) {
					log_info("searching unequal");
					goto mem_free;
				}
			}
		}

		if (node_t->child && *node_t->child && *(topic_queue + 1)) {
			topic_queue++;
			cvector_push_back(node_buf, node);
			cvector_push_back(vec, index);
			node = node_t;

		} else if (*(topic_queue + 1) == NULL) {
			log_info("Search and delete client");
			log_info("node->topic: %s", node->topic);
			break;
		} else {
			log_info("No node and client need to be delete");
			goto mem_free;
		}
	}

	if (node->child) {
		ctxt = delete_dbtree_client(node->child[index], pipe_id);
		delete_dbtree_node(node, index);
	}

	while (!cvector_empty(node_buf) && !cvector_empty(vec)) {
		dbtree_node *t = *(cvector_end(node_buf) - 1);
		int          i = *(cvector_end(vec) - 1);
		cvector_pop_back(node_buf);
		cvector_pop_back(vec);

		delete_dbtree_node(t, i);
	}

mem_free:
	cvector_free(node_buf);
	topic_queue_free(for_free);
	cvector_free(vec);
	pthread_rwlock_unlock(&(db->rwlock));

	return ctxt;
}

void *
dbtree_delete_client(
    dbtree *db, char *topic, uint32_t session_id, uint32_t pipe_id)
{
	return search_and_delete(
	    db, topic, session_id, pipe_id);
}

static void *
insert_dbtree_retain(dbtree_node *node, void *args)
{
	dbtree_retain_msg *retain = (dbtree_retain_msg *) args;
	void *             ret    = NULL;
	pthread_rwlock_wrlock(&(node->rwlock));
	if (node->retain != NULL) {
		ret = node->retain;
	}

	node->retain = retain;

	pthread_rwlock_unlock(&(node->rwlock));

	return ret;
}

void *
dbtree_insert_retain(dbtree *db, char *topic, dbtree_retain_msg *ret_msg)
{
	return search_insert_node(db, topic, ret_msg, insert_dbtree_retain);
}

dbtree_retain_msg **
collect_retain_well(dbtree_retain_msg **vec, dbtree_node *node)
{
	dbtree_node **nodes   = NULL;
	dbtree_node **nodes_t = NULL;
	cvector_push_back(nodes, node);
	while (!cvector_empty(nodes)) {
		for (int i = 0; i < cvector_size(nodes); i++) {
			if (nodes[i]->retain) {
				cvector_push_back(vec, nodes[i]->retain);
			}

			for (int j = 0; j < cvector_size(nodes[i]->child);
			     j++) {
				cvector_push_back(
				    nodes_t, (nodes[i]->child)[j]);
			}
		}

		cvector_free(nodes);
		nodes = NULL;

		for (int i = 0; i < cvector_size(nodes_t); i++) {
			if (nodes_t[i]->retain) {
				cvector_push_back(vec, nodes_t[i]->retain);
			}

			for (int j = 0; j < cvector_size(nodes_t[i]->child);
			     j++) {
				cvector_push_back(
				    nodes, (nodes_t[i]->child)[j]);
			}
		}
		cvector_free(nodes_t);
		nodes_t = NULL;
	}

	return vec;
}

/**
 * @brief collect_retains - Get all retain in nodes
 * @param vec - all clients obey this rule will insert
 * @param nodes - all node need to be compare
 * @param nodes_t - all node need to be compare next time
 * @param topic_queue - topic queue position
 * @return all clients on lots of nodes
 */
static dbtree_retain_msg **
collect_retains(dbtree_retain_msg **vec, dbtree_node **nodes,
    dbtree_node ***nodes_t, char **topic_queue)
{

	while (!cvector_empty(nodes)) {
		dbtree_node **node_t_ = cvector_end(nodes) - 1;
		dbtree_node * node_t  = *node_t_;
		cvector_pop_back(nodes);

		if (node_t == NULL || node_t->child == NULL ||
		    (*(node_t->child)) == NULL) {
			continue;
		}

		dbtree_node * t     = *node_t->child;
		dbtree_node **child = node_t->child;

		if (is_well(*topic_queue)) {
			vec = collect_retain_well(vec, node_t);
			break;
		} else if (is_plus(*topic_queue)) {
			if (*(topic_queue + 1) == NULL) {
				for (int i = 0; i < cvector_size(child); i++) {
					node_t = child[i];
					if (node_t->retain) {
						cvector_push_back(
						    vec, node_t->retain);
					}
				}

			} else {
				for (int i = 0; i < cvector_size(child); i++) {
					node_t = child[i];
					cvector_push_back(
					    ((*nodes_t)), node_t);
				}
			}

		} else {
			bool equal = false;

			if (strcmp(t->topic, *topic_queue)) {
				int index = 0;
				t         = find_next(
                                    node_t, &equal, topic_queue, &index);

			} else {
				equal = true;
			}

			if (equal == true) {
				log_info(
				    "Searching client: %s", node_t->topic);
				if (*(topic_queue + 1) == NULL) {
					if (t->retain) {
						log_info(
						    "Searching client: %s",
						    t->topic);
						cvector_push_back(
						    vec, t->retain);
					}
				} else {
					log_info(
					    "Searching client: %s", t->topic);
					cvector_push_back((*nodes_t), t);
					log_info("add node_t: %s",
					    (*(cvector_end((*nodes_t)) - 1))
					        ->topic);
				}
			}
		}
	}

	return vec;
}

dbtree_retain_msg **
dbtree_find_retain(dbtree *db, char *topic)
{

	if (db == NULL || topic == NULL) {
		log_err("db or topic is NULL");
		return NULL;
	}
	char **topic_queue = topic_parse(topic);
	char **for_free    = topic_queue;
	pthread_rwlock_rdlock(&(db->rwlock));

	dbtree_node *node                 = db->root;
	cvector(dbtree_retain_msg *) rets = NULL;
	cvector(dbtree_node *) nodes      = NULL;
	cvector(dbtree_node *) nodes_t    = NULL;

	if (node->child && *node->child) {
		cvector_push_back(nodes, node);
	}

	while (*topic_queue && (!cvector_empty(nodes))) {

		rets = collect_retains(rets, nodes, &nodes_t, topic_queue);
		topic_queue++;
		if (*topic_queue == NULL) {
			break;
		}
		rets = collect_retains(rets, nodes_t, &nodes, topic_queue);
		topic_queue++;
	}

	pthread_rwlock_unlock(&(db->rwlock));

	topic_queue_free(for_free);
	cvector_free(nodes);
	cvector_free(nodes_t);

	return rets;
}

static void *
delete_dbtree_retain(dbtree_node *node)
{
	if (node == NULL) {
		log_err("node is NULL");
		return NULL;
	}
	void *retain = NULL;
	if (node) {
		retain       = node->retain;
		node->retain = NULL;
	}

	return retain;
}

void *
dbtree_delete_retain(dbtree *db, char *topic)
{
	if (db == NULL || topic == NULL) {
		log_err("db or topic is NULL");
		return NULL;
	}
	pthread_rwlock_wrlock(&(db->rwlock));

	char **       topic_queue = topic_parse(topic);
	char **       for_free    = topic_queue;
	dbtree_node * node        = db->root;
	dbtree_node **node_buf    = NULL;
	int *         vec         = NULL;
	void *        ret         = NULL;
	int           index       = 0;

	while (*topic_queue && node->child && *node->child) {
		index               = 0;
		dbtree_node *node_t = *node->child;
		log_info("topic is: %s, node->topic is: %s", *topic_queue,
		    node_t->topic);
		if (strcmp(node_t->topic, *topic_queue)) {
			bool equal = false;

			// TODO node_t or node->child[index], to determine if
			// node_t is needed
			node_t = find_next(node, &equal, topic_queue, &index);
			if (equal == false) {
				log_info("searching unequal");
				goto mem_free;
			}
		}

		if (node_t->child && *node_t->child && *(topic_queue + 1)) {
			topic_queue++;
			cvector_push_back(node_buf, node);
			cvector_push_back(vec, index);
			node = node_t;

		} else if (*(topic_queue + 1) == NULL) {
			log_info("Search and delete retain");
			log_info("node->topic: %s", node->topic);
			break;
		} else {
			log_info("No node and client need to be delete");
			goto mem_free;
		}
	}

	if (node->child) {
		ret = delete_dbtree_retain(node->child[index]);
		// print_client(node->child[index]->clients);
		delete_dbtree_node(node, index);
		// print_client(node->child[index]->clients);
	}

	// dbtree_print(dbtree);

	while (!cvector_empty(node_buf) && !cvector_empty(vec)) {
		dbtree_node *t = *(cvector_end(node_buf) - 1);
		int          i = *(cvector_end(vec) - 1);
		cvector_pop_back(node_buf);
		cvector_pop_back(vec);

		delete_dbtree_node(t, i);
		// dbtree_print(dbtree);
	}

	pthread_rwlock_unlock(&(db->rwlock));

mem_free:
	cvector_free(node_buf);
	topic_queue_free(for_free);
	cvector_free(vec);

	return ret;
}

bool
dbtree_check_shared_sub(const char *topic)
{
	if (topic == NULL) {
		return false;
	}

	char *t = NULL;
	if (NULL == (t = strchr(topic, '$'))) {
		return false;
	}

	if (NULL == strstr(t, "share")) {
		return false;
	}

	return true;
}

static void **
dbtree_shared_iterate_client(dbtree_client ***v)
{
	cvector(void *) ctxts   = NULL;
	cvector(uint32_t *) ids = NULL;

	if (v) {
		for (int i = 0; i < cvector_size(v); ++i) {
			// Dispatch strategy.
#ifdef RANDOM
			int t = rand();
#elif defined(ROUND_ROBIN)
			int t = acnt;
#endif
			int j = t % cvector_size(v[i]);

			// printf("acnt: %d\n", acnt);
			// printf("j: %d\n", j);
			// printf("size: %d\n", cvector_size(v[i]));
			// bool equal = false;

			int index = 0;

			if (false ==
			    binary_search((void **) ids, 0, &index,
			        &v[i][j]->pipe_id, ids_cmp)) {
				if (cvector_empty(ids) ||
				    index == cvector_size(ids)) {
					cvector_push_back(
					    ids, &v[i][j]->pipe_id);
				} else {
					cvector_insert(
					    ids, index, &v[i][j]->pipe_id);
				}

				void *ctxt = v[i][j]->ctxt;
				if (0 != dbtree_ctxt_get_ref(ctxt)) {
					dbtree_ctxt_clone((dbtree_ctxt*) ctxt);
					cvector_push_back(ctxts, ctxt);
				}
			}
		}
		cvector_free(ids);
		acnt++;
		if (acnt == INT_MAX) {
			acnt = 0;
		}
	}

	return ctxts;
}

void **
dbtree_find_shared_clients(dbtree *db, char *topic)
{
	pthread_rwlock_rdlock(&(db->rwlock));
	dbtree_node *node                              = db->root;
	cvector(dbtree_client **) ctxts                = NULL;
	cvector(dbtree_node *) nodes                   = NULL;
	cvector(dbtree_node *) nodes_t                 = NULL;
	bool  equal                                    = false;
	char *t                                        = "$share";
	int   index;

	if (node == NULL) {
		pthread_rwlock_unlock(&(db->rwlock));
		return NULL;
	}

	dbtree_node *shared = find_next(node, &equal, &t, &index);

	if (equal == false || shared == NULL || shared->child == NULL) {
		pthread_rwlock_unlock(&(db->rwlock));
		return NULL;
	}

	dbtree_node **nlist = shared->child;

	char **topic_queue = topic_parse(topic);
	char **for_free    = topic_queue;

	for (int i = 0; i < cvector_size(nlist); i++) {
		dbtree_node *node = nlist[i];
		if (node->child && *node->child) {
			cvector_push_back(nodes, node);
		}
	}

	log_info("nodes size: %lu", cvector_size(nlist));
	while (*topic_queue && (!cvector_empty(nodes))) {

		ctxts = collect_clients(ctxts, nodes,
		    &nodes_t, topic_queue);
		topic_queue++;
		if (*topic_queue == NULL) {
			break;
		}
		ctxts = collect_clients(ctxts, nodes_t,
		    &nodes, topic_queue);
		topic_queue++;
	}

	void **ret = (void **) dbtree_shared_iterate_client(ctxts);
	pthread_rwlock_unlock(&(db->rwlock));
	topic_queue_free(for_free);
	cvector_free(nodes);
	cvector_free(nodes_t);
	cvector_free(ctxts);

	return ret;
}

void **
dbtree_find_shared_sub_clients(
    dbtree *db, char *topic)
{
	return dbtree_find_shared_clients(db, topic);
}
