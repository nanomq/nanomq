//
// Copyright 2020 NanoMQ Team, Inc. <jaylin@emqx.io> //
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <assert.h>
#include <string.h>

#include "include/cvector.h"
#include "include/dbg.h"
#include "include/hash.h"
#include "include/mqtt_db.h"
#include "include/zmalloc.h"

/**
 * @brief print_client - A way to print client in vec.
 * @param v - normally v is an dynamic array
 * @return void
 */
static void
print_client(s_client **v)
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
 * @brief binary_search - A iterative binary search function.
 * @param vec - normally vec is an dynamic array
 * @param l - it is the left boundry of the vec
 * @param index - index is the result we search
 * @param e - e contain message we want to search
 * @param cmp - cmp is a compare method
 * @return true or false, if we find or not
 */
static bool
binary_search(
    void **vec, int l, int *index, void *e, int (*cmp)(void *x, void *y))
{

	int r = cvector_size(vec) - 1;
	int m = 0;

	// if we do not find the element
	// vec = [0, 1, 3, 4], e = 2 ,
	// m will be 2, index = 2 ok
	// vec = [0, 1, 2, 4], e = 3 ,
	// m will be 2, index = 2 error,
	// index = 2 + add(1) ok
	int add = 0;

	// log("l: %d", l);
	// log("r: %d", r);

	while (l <= r) {
		m = l + (r - l) / 2;

		// Check if x is present at mid
		if (cmp(vec[m], e) == 0) {
			*index = m;
			return true;
		}
		// log("m: %d", m);

		// If x greater, ignore left half
		if (cmp(vec[m], e) < 0) {
			l   = m + 1;
			add = 1;

			// If x is smaller, ignore right half
		} else {
			r   = m - 1;
			add = 0;
		}
	}
	// log("m: %d", m);

	// if we reach here, then element was
	// not present
	*index = m + add;
	return false;
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
		// log("%s", t);
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
	assert(topic != NULL);

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

	zfree(tt);
	topic_queue = NULL;
}

// static void print_db_node(db_node *node)
// {
//         printf("topic:    %s\n", node->topic);
//
//         if (node->clients) {
//                 cvector(s_client*) clients = node->clients;
//                 for (int i = 0; i < cvector_size(clients); i++) {
//                         printf("id:       %s\n", clients[i]->id);
//                 }
//         }
//
// }

/**
 * @brief print_db_tree - Print db_tree for debug.
 * @param db_tree - db_tree
 * @return void
 */
#ifdef NOLOG
void
print_db_tree(db_tree *db)
{
	return;
}
#else
void
print_db_tree(db_tree *db)
{
	assert(db);
	db_node *node = db->root;
	db_node **nodes = NULL;
	db_node **nodes_t = NULL;
	cvector_push_back(nodes, node);
	puts("___________PRINT_DB_TREE__________");
	while (!cvector_empty(nodes)) {
		for (int i = 0; i < cvector_size(nodes); i++) {
			printf("%s\t", nodes[i]->topic);
			// printf("%s ", nodes[i]->topic);
			// printf("%p\t", nodes[i]);

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
			printf("%s\t", nodes_t[i]->topic);
			// printf("%s ", nodes_t[i]->topic);
			// printf("%p\t", nodes_t[i]);

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
	puts("___________PRINT_DB_TREE__________");
}
#endif

/**
 * @brief skip_wildcard - To get left boundry of binary search
 * @param node - db_node
 * @return l - left boundry
 */
static int
skip_wildcard(db_node *node)
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
 * @param node - db_node
 * @param equal - a return state value
 * @param topic_queue - topic queue
 * @param index - search index will be return
 * @return db_node we find or original node
 */
// TODO topic or topic queue
// TODO return NULL if no find ?
static db_node *
find_next(db_node *node, bool *equal, char **topic_queue, int *index)
{
	if (node == NULL || node->child == NULL) {
		return NULL;
	}

	cvector(db_node *) t = node->child;

	int l = skip_wildcard(node);

	if (true ==
	    binary_search((void **) t, l, index, *topic_queue, node_cmp)) {
		*equal = true;
		return t[*index];
	}

	return node;
}

/**
 * @brief new_db_client - create a client
 * @param id - client id
 * @param ctxt - client ctxt
 * @return s_client*
 */
static s_client *
new_db_client(char *id, void *ctxt, uint32_t pipe_id)
{
	s_client *client = NULL;
	client           = (s_client *) zmalloc(sizeof(s_client));

	// client->id = zstrdup(id);
	client->pipe_id = pipe_id;
	client->ctxt    = ctxt;
	return client;
}

/**
 * @brief db_client_free - free a client memory
 * @param id - client id
 * @return s_client*
 */
static void *
db_client_free(s_client *client)
{
	void *ctxt = NULL;
	if (client) {
		// if (client->id) {
		//         zfree(client->id);
		//         client->id = NULL;
		// }
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
 * @brief new_db_node - create a node
 * @param topic - topic
 * @return db_node*
 */
static db_node *
new_db_node(char *topic)
{
	db_node *node = NULL;
	node          = (db_node *) zmalloc(sizeof(db_node));

	node->topic = zstrdup(topic);

	node->retain  = NULL;
	node->child   = NULL;
	node->clients = NULL;
	node->well    = -1;
	node->plus    = -1;
	pthread_rwlock_init(&(node->rwlock), NULL);
	return node;
}

/**
 * @brief db_node_free - Free a node memory
 * @param node - db_node *
 * @return void
 */
static void
db_node_free(db_node *node)
{
	if (node) {
		if (node->topic) {
			zfree(node->topic);
			node->topic = NULL;
			pthread_rwlock_destroy(&(node->rwlock));
		}
		zfree(node);
		node = NULL;
	}
}

/**
 * @brief create_db_tree - Create a db_tree, declare a global variable as func
 * para
 * @param db - db_tree
 * @return void
 */
void
create_db_tree(db_tree **db)
{
	*db = (db_tree *) zmalloc(sizeof(db_tree));
	memset(*db, 0, sizeof(db_tree));

	db_node *node = new_db_node("\0");
	(*db)->root   = node;
	pthread_rwlock_init(&((*db)->rwlock), NULL);
	return;
}

// db_tree *create_db_tree(void)
// {
//         db_tree *db = (db_tree *)zmalloc(sizeof(db_tree));
//         memset(db, 0, sizeof(db_tree));
//
//         db_node *node = new_db_node("\0");
//         db->root = node;
//         pthread_rwlock_init (&(db->rwlock), NULL);
//         return db;
// }

/**
 * @brief destory_db_tree - Destory db tree
 * @param db - db_tree
 * @return void
 */
void
destory_db_tree(db_tree *db)
{
	if (db) {
		db_node_free(db->root);
		zfree(db);
		db = NULL;
	}

	pthread_rwlock_destroy(&(db->rwlock));
}

/**
 * @brief insert_db_client - insert a client on the right position
 * @param node - db_node
 * @param args - client
 * @return
 */
static void *
insert_db_client(db_node *node, void *args)
{
	pthread_rwlock_wrlock(&(node->rwlock));

	int       index  = 0;
	s_client *client = (s_client *) args;

	// printf("pipe_id is : %d\n", client->pipe_id);
	if (false ==
	    binary_search((void **) node->clients, 0, &index,
	        /*client->id,*/ &(client->pipe_id), client_cmp)) {
		if (index == cvector_size(node->clients)) {
			cvector_push_back(node->clients, client);
		} else {
			cvector_insert(node->clients, index, client);
		}
	} else {
		// TODO lazy binding
		db_client_free(client);
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
 * @brief wildcard_dealer - Deal contains of wildcard
 * @param node - db_node
 * @param topic_queue - topic queue position
 * @param client - client info
 * @return void
 */

// TODO
// static wildcard_dealer(db_node *node, char **topic_queue, s_client *client,
// bool(*check(char *topic))
// {
//         if (is_well(*topic_queue)) {
//                 if (node->well != -1) {
//                         new_node = node->child[node->well];
//                 } else {
//                         if (node->plus == 0) {
//                                 node->plus = 1;
//                         }
//
//                         node->well = 0;
//                         new_node = new_db_node(*topic_queue);
//                         cvector_insert(node->child, node->well, new_node);
//                 }
//
//         }
// }

/**
 * @brief insert_db_node - insert node until topic_queue is NULL
 * @param node - db_node
 * @param topic_queue - topic queue position
 * @param client - client info
 * @return void
 */
static db_node *
insert_db_node(db_node *node, char **topic_queue)
{
	assert(node && topic_queue);

	while (*topic_queue) {
		db_node *new_node = NULL;

		if (is_well(*topic_queue)) {
			if (node->well != -1) {
				new_node = node->child[node->well];
			} else {
				if (node->plus == 0) {
					node->plus = 1;
				}

				node->well = 0;
				new_node   = new_db_node(*topic_queue);
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
				new_node   = new_db_node(*topic_queue);
				cvector_insert(
				    node->child, node->plus, new_node);
			}
			// log("plus: topic is: %s, node->topic: %s",
			// *topic_queue, node->topic); log("node: %p, new node:
			// %p, child: %p", node, new_node, *node->child);
		} else {
			int l = skip_wildcard(node);

			// TODO 是否会有找到的情况
			int index = 0;
			if (false ==
			    binary_search((void **) node->child, l, &index,
			        *topic_queue, node_cmp)) {
				new_node = new_db_node(*topic_queue);
				//  TODO
				if (index == cvector_size(node->child)) {
					cvector_push_back(
					    node->child, new_node);
				} else {
					cvector_insert(
					    node->child, index, new_node);
				}
			} else {
				new_node = node->child[index];
			}

			log("@@@@@@index@@@@@@ : %d", index);
			// cvector_push_back(node->child, new_node);
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
 * @param db - db_node
 * @param topic - topic
 * @param client - client
 * @return
 */
static void *
search_insert_node(db_tree *db, char *topic, void *args,
    void *(*inserter)(db_node *node, void *args))
{
	assert(db->root && topic);

	char **  topic_queue = topic_parse(topic);
	char **  for_free    = topic_queue;
	db_node *node        = db->root;

	pthread_rwlock_wrlock(&(db->rwlock));

	// while db_tree is NULL, we will insert directly.
	if (!(node->child && *node->child)) {
		node = insert_db_node(node, topic_queue);
	} else {

		while (*topic_queue && node->child && *node->child) {
			db_node *node_t = *node->child;
			log("topic is: %s, node->topic is: %s", *topic_queue,
			    node_t->topic);
			if (strcmp(node_t->topic, *topic_queue)) {
				bool equal = false;
				int  index = 0;

				// TODO find_hash/plus

				node_t = find_next(
				    node, &equal, topic_queue, &index);
				if (equal == false) {
					/*
					 ** If no node is matched with topic
					 ** insert node until topic_queue
					 ** is NULL
					 */
					log("searching unequal");
					node = insert_db_node(
					    node_t, topic_queue);
					break;
				}
			}

			if (node_t->child && *node_t->child &&
			    *(topic_queue + 1)) {
				topic_queue++;
				node = node_t;
			} else if (*(topic_queue + 1) == NULL) {
				log("Search and insert client");
				node = node_t;
				// TODO
				// insert_db_client(node_t, client);
				break;
			} else {
				log("Insert node and client");
				node = insert_db_node(node_t, topic_queue);
				break;
			}
		}
	}

	void *ret = inserter(node, args);

	pthread_rwlock_unlock(&(db->rwlock));
	topic_queue_free(for_free);
	return ret;
}

/**
 * @brief search_and_insert - check if this
 * topic and client id is exist on the tree, if
 * there is not exist, this func will insert
 * related node and client on the tree
 * @param db - db_node
 * @param topic - topic
 * @param client - client
 * @return
 */
void *
search_and_insert(
    db_tree *db, char *topic, char *id, void *ctxt, uint32_t pipe_id)
{

	s_client *client = new_db_client(id, ctxt, pipe_id);
	return search_insert_node(db, topic, client, insert_db_client);
}

typedef s_client *s_client_ptr;
typedef db_node * db_node_ptr;

/**
 * @brief collect_clients - Get all clients in nodes
 * @param vec - all clients obey this rule will insert
 * @param nodes - all node need to be compare
 * @param nodes_t - all node need to be compare next time
 * @param topic_queue - topic queue position
 * @return all clients on lots of nodes
 */
static s_client ***
collect_clients(
    s_client ***vec, db_node **nodes, db_node ***nodes_t, char **topic_queue)
{

	while (!cvector_empty(nodes)) {
		db_node **node_t_ = cvector_end(nodes) - 1;
		db_node * node_t  = *node_t_;
		cvector_pop_back(nodes);

		if (node_t == NULL || node_t->child == NULL ||
		    (*(node_t->child)) == NULL) {
			continue;
		}

		db_node * t     = *node_t->child;
		db_node **child = node_t->child;

		if (node_t->well != -1) {
			if (!cvector_empty(child[node_t->well]->clients)) {
				log("Find # tag");
				cvector_push_back(
				    vec, child[node_t->well]->clients);
			}
		}

		if (node_t->plus != -1) {
			if (*(topic_queue + 1) == NULL) {
				log("add + clients");
				if (!cvector_empty(
				        child[node_t->plus]->clients)) {
					cvector_push_back(
					    vec, child[node_t->plus]->clients);
				}

			} else {
				log("add +");
				cvector_push_back(
				    (*nodes_t), child[node_t->plus]);
				log("add node_t: %s",
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
			log("Searching client: %s", t->topic);
			if (*(topic_queue + 1) == NULL) {
				if (!cvector_empty(t->clients)) {
					log("Searching client: %s", t->topic);
					cvector_push_back(vec, t->clients);
				}
			} else {
				log("Searching client: %s", t->topic);
				cvector_push_back((*nodes_t), t);
				log("add node_t: %s",
				    (*(cvector_end((*nodes_t)) - 1))->topic);
			}
		}
	}

	return vec;
}

/**
 * @brief iterate_client - Deduplication for all clients
 * @param v - client
 * @return s_client
 */
// TODO polish
static void **
iterate_client(s_client ***v)
{
	cvector(void *) ctxts = NULL;
	// cvector(char*) ids = NULL;
	cvector(uint32_t) ids = NULL;

	if (v) {
		for (int i = 0; i < cvector_size(v); ++i) {
			for (int j = 0; j < cvector_size(v[i]); j++) {
				bool equal = false;
				for (int k = 0; k < cvector_size(ids); k++) {
					// if (!strcmp(ids[k], v[i][j]->id)) {
					if (ids[k] == v[i][j]->pipe_id) {
						equal = true;
						break;
					}
				}

				if (equal == false) {
					cvector_push_back(
					    ctxts, v[i][j]->ctxt);
					// TODO  binary sort and
					// cvector_insert();
					cvector_push_back(
					    ids, v[i][j]->pipe_id);
				}

				log("client id: %d", v[i][j]->pipe_id);
			}
		}
		cvector_free(ids);
	}

	return ctxts;
}

/**
 * @brief search_client - Get all subscribers to this topic.
 * @param db - db_tree
 * @param topic - topic
 * @return s_client
 */
void **
search_client(db_tree *db, char *topic)
{
	assert(db && topic);
	char **topic_queue = topic_parse(topic);
	char **for_free    = topic_queue;

	pthread_rwlock_rdlock(&(db->rwlock));

	db_node *node              = db->root;
	cvector(s_client **) ctxts = NULL;
	cvector(db_node *) nodes   = NULL;
	cvector(db_node *) nodes_t = NULL;

	if (node->child && *node->child) {
		cvector_push_back(nodes, node);
	}

	// log("node->topic %s, topic_queue %s", node->topic, *topic_queue);
	// printf("node->topic %s, topic_queue %s\n", node->topic,
	// *topic_queue);

	while (*topic_queue && (!cvector_empty(nodes))) {

		ctxts = collect_clients(ctxts, nodes, &nodes_t, topic_queue);
		topic_queue++;
		if (*topic_queue == NULL) {
			break;
		}
		ctxts = collect_clients(ctxts, nodes_t, &nodes, topic_queue);
		topic_queue++;
	}

	void **ret = iterate_client(ctxts);
	pthread_rwlock_unlock(&(db->rwlock));

	topic_queue_free(for_free);
	cvector_free(nodes);
	cvector_free(nodes_t);
	cvector_free(ctxts);

	return ret;
}

/**
 * @brief delete_db_client - delete db client
 * @param node - db_node
 * @param id - client id
 * @param pipe_id - pipe id
 * @return
 */
static void *
delete_db_client(db_node *node /*, char *id*/, uint32_t pipe_id)
{
	int   index = 0;
	void *ctxt  = NULL;

	pthread_rwlock_wrlock(&(node->rwlock));
	// TODO maybe ctxt need to be protected
	print_client(node->clients);
	if (true ==
	    binary_search(
	        (void **) node->clients, 0, &index, &pipe_id, client_cmp)) {
		s_client *c = node->clients[index];
		cvector_erase(node->clients, index);
		print_client(node->clients);
		ctxt = db_client_free(c);

		if (cvector_empty(node->clients)) {
			cvector_free(node->clients);
			node->clients = NULL;
		} else {
			print_client(node->clients);
		}
	}
	pthread_rwlock_unlock(&(node->rwlock));
	return ctxt;
}

/**
 * @brief check_set_wildcard - Chech and set wildward flag bit
 * @param db - db_node
 * @param index - index
 * @return
 */

// static db_node *check_set_wildcard(db_node *node, int index)
// {
//
//         // if index = 0, maybe node->plus && node->well
//         // should --, if index = 1, we just at most 1.
//         if (index == 0) {
//                 if (node->plus >= 0) {
//                         node->plus--;
//                 }
//
//                 if (node->well >= 0) {
//                         node->well--;
//                 }
//
//         }
//
//         if (index == 1) {
//                 if (node->plus == 1) {
//                         node->plus = -1;
//                 }
//
//                 if (node->well == 1) {
//                         node->well = -1;
//                 }
//
//         }
//
//         return node;
// }

/**
 * @brief delete_db_node - delete db node
 * @param db - db_node
 * @param index - index
 * @return
 */
static int
delete_db_node(db_node *node, int index)
{
	pthread_rwlock_wrlock(&(node->rwlock));
	db_node *node_t = node->child[index];
	log("index: %d, node: %s", index, node_t->topic);
	// TODO plus && well

	if (cvector_empty(node_t->child) && cvector_empty(node_t->clients)) {
		zfree(node_t->topic);
		// pthread_rwlock_destroy (&(node_t->rwlock));
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

/**
 * @brief search_and_delete - check if this
 * topic and client id is exist on the tree, if
 * there is exist, this func will delete
 * related node and client on the tree
 * @param db - db_node
 * @param topic - topic
 * @param client - client
 * @return ctxt or NULL, if client can be delete or not
 */
void *
search_and_delete(db_tree *db, char *topic, /*char *id*/ uint32_t pipe_id)
{
	assert(db->root && topic);
	pthread_rwlock_wrlock(&(db->rwlock));

	char **   topic_queue = topic_parse(topic);
	char **   for_free    = topic_queue;
	db_node * node        = db->root;
	db_node **node_buf    = NULL;
	void *    ctxt        = NULL;
	int *     vec         = NULL;
	int       index       = 0;

	while (*topic_queue && node->child && *node->child) {
		index           = 0;
		db_node *node_t = *node->child;
		log("topic is: %s, node->topic is: %s", *topic_queue,
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
					log("searching unequal");
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
			log("Search and delete client");
			log("node->topic: %s", node->topic);
			break;
		} else {
			log("No node and client need to be delete");
			goto mem_free;
		}
	}

	if (node->child) {
		ctxt = delete_db_client(node->child[index], pipe_id);
		// print_client(node->child[index]->clients);
		delete_db_node(node, index);
		// print_client(node->child[index]->clients);
	}

	// print_db_tree(db);

	while (!cvector_empty(node_buf) && !cvector_empty(vec)) {
		db_node *t = *(cvector_end(node_buf) - 1);
		int      i = *(cvector_end(vec) - 1);
		cvector_pop_back(node_buf);
		cvector_pop_back(vec);

		delete_db_node(t, i);
		// print_db_tree(db);
	}

	pthread_rwlock_unlock(&(db->rwlock));

mem_free:
	cvector_free(node_buf);
	topic_queue_free(for_free);
	cvector_free(vec);

	return ctxt;
}

static void *
insert_db_retain(db_node *node, void *args)
{
	retain_msg *retain = (retain_msg *) args;
	void *      ret    = NULL;
	pthread_rwlock_wrlock(&(node->rwlock));
	if (node->retain != NULL) {
		ret = node->retain;
	}

	node->retain = retain;

	pthread_rwlock_unlock(&(node->rwlock));

	return ret;
}

/**
 * @brief search_insert_retain - check if this
 * topic and client id is exist on the tree, if
 * there is not exist, this func will insert
 * related node and client on the tree
 * @param db - db_node
 * @param topic - topic
 * @param client - client
 * @return
 */
void *
search_insert_retain(db_tree *db, char *topic, retain_msg *ret_msg)
{
	return search_insert_node(db, topic, ret_msg, insert_db_retain);
}

retain_msg **
collect_retain_well(retain_msg **vec, db_node *node)
{
	db_node **nodes   = NULL;
	db_node **nodes_t = NULL;
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
static retain_msg **
collect_retains(
    retain_msg **vec, db_node **nodes, db_node ***nodes_t, char **topic_queue)
{

	while (!cvector_empty(nodes)) {
		db_node **node_t_ = cvector_end(nodes) - 1;
		db_node * node_t  = *node_t_;
		cvector_pop_back(nodes);

		if (node_t == NULL || node_t->child == NULL ||
		    (*(node_t->child)) == NULL) {
			continue;
		}

		db_node * t     = *node_t->child;
		db_node **child = node_t->child;

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
				log("Searching client: %s", node_t->topic);
				if (*(topic_queue + 1) == NULL) {
					if (t->retain) {
						log("Searching client: %s",
						    t->topic);
						cvector_push_back(
						    vec, t->retain);
					}
				} else {
					log("Searching client: %s", t->topic);
					cvector_push_back((*nodes_t), t);
					log("add node_t: %s",
					    (*(cvector_end((*nodes_t)) - 1))
					        ->topic);
				}
			}
		}
	}

	return vec;
}

/**
 * @brief search_retain - Get all retain message to this topic.
 * @param db - db_tree
 * @param topic - topic
 * @return retain_msg pointer vector
 */
retain_msg **
search_retain(db_tree *db, char *topic)
{

	assert(db && topic);
	char **topic_queue = topic_parse(topic);
	char **for_free    = topic_queue;
	pthread_rwlock_rdlock(&(db->rwlock));

	db_node *node              = db->root;
	cvector(retain_msg *) rets = NULL;
	cvector(db_node *) nodes   = NULL;
	cvector(db_node *) nodes_t = NULL;

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
delete_db_retain(db_node *node)
{
	assert(node);
	void *retain = NULL;
	if (node) {
		retain       = node->retain;
		node->retain = NULL;
	}

	return retain;
}

/**
 * @brief search_and_delete - check if this
 * topic and client id is exist on the tree, if
 * there is exist, this func will delete
 * related node and client on the tree
 * @param db - db_node
 * @param topic - topic
 * @param client - client
 * @return ctxt or NULL, if client can be delete or not
 */
void *
search_delete_retain(db_tree *db, char *topic)
{
	assert(db->root && topic);
	pthread_rwlock_wrlock(&(db->rwlock));

	char **   topic_queue = topic_parse(topic);
	char **   for_free    = topic_queue;
	db_node * node        = db->root;
	db_node **node_buf    = NULL;
	int *     vec         = NULL;
	void *    ret         = NULL;
	int       index       = 0;

	while (*topic_queue && node->child && *node->child) {
		index           = 0;
		db_node *node_t = *node->child;
		log("topic is: %s, node->topic is: %s", *topic_queue,
		    node_t->topic);
		if (strcmp(node_t->topic, *topic_queue)) {
			bool equal = false;

			// TODO node_t or node->child[index], to determine if
			// node_t is needed
			node_t = find_next(node, &equal, topic_queue, &index);
			if (equal == false) {
				log("searching unequal");
				goto mem_free;
			}
		}

		if (node_t->child && *node_t->child && *(topic_queue + 1)) {
			topic_queue++;
			cvector_push_back(node_buf, node);
			cvector_push_back(vec, index);
			node = node_t;

		} else if (*(topic_queue + 1) == NULL) {
			log("Search and delete retain");
			log("node->topic: %s", node->topic);
			break;
		} else {
			log("No node and client need to be delete");
			goto mem_free;
		}
	}

	if (node->child) {
		ret = delete_db_retain(node->child[index]);
		// print_client(node->child[index]->clients);
		delete_db_node(node, index);
		// print_client(node->child[index]->clients);
	}

	// print_db_tree(db);

	while (!cvector_empty(node_buf) && !cvector_empty(vec)) {
		db_node *t = *(cvector_end(node_buf) - 1);
		int      i = *(cvector_end(vec) - 1);
		cvector_pop_back(node_buf);
		cvector_pop_back(vec);

		delete_db_node(t, i);
		// print_db_tree(db);
	}

	pthread_rwlock_unlock(&(db->rwlock));

mem_free:
	cvector_free(node_buf);
	topic_queue_free(for_free);
	cvector_free(vec);

	return ret;
}

void
hash_add_alias(int alias, char *topic)
{
	assert(topic);
	push_val(alias, topic);
}

char *
hash_check_alias(int alias)
{
	return get_val(alias);
}

void
hash_del_alias(int alias)
{
	del_val(alias);
}
