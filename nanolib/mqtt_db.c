#include <string.h>
#include <assert.h>

#include "include/mqtt_db.h"
#include "include/zmalloc.h"
#include "include/hash.h"
#include "include/dbg.h"


/* 
 ** Create a db_tree
 ** Declare a global variable as func para 
 ** struct db_tree *db;
 */
void create_db_tree(struct db_tree **db)
{
	log_info("CREATE_DB_TREE");
	*db = (struct db_tree *)zmalloc(sizeof(struct db_tree));
	memset(*db, 0, sizeof(struct db_tree));

	struct db_node *node = new_db_node("\0");
	(*db)->root = node;
	return;
}

/*
 ** Destory db tree 
 ** destory all node & db_tree
 */
void destory_db_tree(struct db_tree *db)
{
	log_info("DESTORY_DB_TREE");
	/* TODO */

}

/*
 ** Print db_tree
 ** For debugging, you can output all node 
 ** & node info
 */
#ifdef NOLOG
void print_db_tree(struct db_tree *db)
{
	return;
}
#else
void print_db_tree(struct db_tree *db)
{
	assert(db);
	struct db_nodes *tmps = NULL;
	struct db_nodes *tmps_end = NULL;
	tmps = (struct db_nodes*)zmalloc(sizeof(struct db_nodes));
	tmps->node = db->root;
	int size = 1;
	int len = size;
	tmps->next = NULL;
	tmps_end = tmps;

	puts("-------------------DB_TREE---------------------");
	puts("TOPIC | HASHTAG&PLUS | CLIENTID | FATHER_NODE");
	puts("-----------------------------------------------");

	while (tmps) {
		size = 0;
		while (len-- && tmps) {
			struct db_node *tmp = tmps->node;
			while (tmp) {
				printf("\"%s\" ", tmp->topic);
				printf("%d", tmp->hashtag);
				printf("%d ", tmp->plus);
				if (tmp->sub_client) {
					printf("%s ", tmp->sub_client->id);
					if (tmp->sub_client->next) {
						printf("and more ");
					} else {
						printf("no more ");
					}

				} else {
					printf("-- ");
				}
				if (tmp->up) {
					if (strcmp("#", tmp->topic)) {
						printf("\"%s\"\t ", tmp->up->topic);
					} else {
						printf("<-\t ");
					}

				} else {
					printf("--\t");
				}

				if (tmp->down) {
					// debug("sth new");
					size++;
					tmps_end->next = (struct db_nodes*)zmalloc(sizeof(struct db_nodes));
					tmps_end = tmps_end->next;
					tmps_end->node = tmp->down;
					tmps_end->next = NULL;
				}
				if (tmp) {
					// debug("tmp next");
					tmp = tmp->next;
				}
			}
			// debug("tmps next");
			tmps = tmps->next;
		}

		printf("\n");
		if (size == 0) {
			break;
		}
		puts("----------------------------------------------");

		len = size;

	}

	puts("-------------------DB_TREE---------------------\n");
}

#endif

/*
 ** Determine if the current topic data is "#"
 ** or not.
 */
bool check_hashtag(char *topic_data)
{
	if (topic_data == NULL) {
		return false;
	}
	return !strcmp(topic_data, "#");
}

/*
 ** Determine if the current topic data is "+"
 ** or not.
 */
bool check_plus(char *topic_data)
{
	if (topic_data == NULL) {
		return false;
	}
	return !strcmp(topic_data, "+");
}

struct db_node *new_db_node(char *topic)
{
	struct db_node *node = NULL;
	node = (struct db_node*)zmalloc(sizeof(struct db_node));
	node->topic = (char*)zmalloc(strlen(topic)+1);
	memcpy(node->topic, topic, strlen(topic)+1);
	log("new_db_node %s", node->topic);
	node->hashtag = false;
	node->plus = false;
	node->next = NULL;
	node->down = NULL;
	node->up = NULL;
	node->sub_client = NULL;
	return node;
}

void delete_db_node(struct db_node *node)
{
	if (node) {
		log("delete_db_node %s", node->topic);
		if (node->topic) {
			zfree(node->topic);
		}
		node->topic = NULL;
		node->up = NULL;
		node->next = NULL;
		node->down = NULL;
		zfree(node);
	}
	node = NULL;
}

void set_db_node(struct db_node *node, char **topic_queue)
{
	if (node) {
		debug("set_db_node topic is %s", *topic_queue);
		node->down = new_db_node(*(topic_queue));
		node->down->up = node;
		node->down->next = NULL;
		node->down->down = NULL;
	} else {
		/* TODO */
	}
}

void insert_db_node(struct db_node *new_node, struct db_node *old_node)
{
	log("insert_db_node %s", new_node->topic);
	if (old_node->next != new_node) {
		struct db_node *tmp_node = NULL;
		tmp_node = old_node->next;
		old_node->next = new_node;
		new_node->next = tmp_node->next;
	}
	new_node->up = old_node->up ? old_node->up : old_node;
	return;
}

/* 
 ** Add nodes when the sub node is not found in the tree. 
 ** You need do serach_node and set client before add_node.
 ** input is the result of search_node, id is the result 
 ** of set_client.
 */
void add_node(struct topic_and_node *input, struct client *id)
{
	log_info("ADD_NODE_START");
	assert(input);
	struct db_node *tmp_node = NULL;
	struct db_node *new_node = NULL;
	char **topic_queue = input->topic;

	if (topic_queue == NULL) {
		log("Topic_queue is NULL, no topic is needed add!");
		return;
	}

	if (input->t_state == EQUAL) {
		/* 
		 ** # is the last string in topic 
		 */
		if (input->hashtag) {
			input->node->hashtag = true;
			if (input->node->next) {
				new_node = new_db_node(*(++topic_queue));
				insert_db_node(new_node, input->node);
			} else {
				input->node->next = new_db_node(*(++topic_queue));
				insert_db_node(input->node->next, input->node);
				new_node = input->node->next;
			}

		} else {
			set_db_node(input->node, ++topic_queue);
			if (check_plus(*(topic_queue))) {
				debug("equal, plus is true");
				input->node->plus = true;
			}
			new_node = input->node->down;
		}

	} else {
		new_node = new_db_node(*topic_queue);
		new_node->up =  input->node;

		if (check_plus(*topic_queue)) {
			debug("unequal, plus is true");
			input->node->plus = true;
			tmp_node = input->node->down;
			input->node->down = new_node;
			new_node->next = tmp_node;
		} else {
			debug("unequal, plus is not true");
			if (input->node->down->next) {
				if (input->node->down->hashtag) {
					tmp_node = input->node->down->next->next;
					input->node->down->next->next = new_node;
					new_node->next = tmp_node;

				} else {
					tmp_node = input->node->down->next;
					input->node->down->next = new_node;
					new_node->next = tmp_node;
				}
			} else {
				input->node->down->next = new_node;
			}
		}
	}

	while (*(++topic_queue)) {
		if (check_hashtag(*topic_queue)) {
			debug("set hashtag is true");
			new_node->hashtag = true;
			/*
			 ** TODO delete it or not
			 */
			if (new_node->next) {
				tmp_node = new_db_node(*topic_queue);
				tmp_node->up = new_node->up ? new_node->up : NULL;
				tmp_node->down = NULL;
				tmp_node->next = new_node->next;
				new_node->next = tmp_node;

			} else {
				new_node->next = new_db_node(*topic_queue);
				insert_db_node(new_node->next, new_node);
			}
			new_node = new_node->next;
		} else {
			if (check_plus(*topic_queue)) {
				new_node->plus = true;
			}
			set_db_node(new_node, topic_queue);
			new_node = new_node->down;
		}
	}

	input->node = new_node;

	if (id) {
		new_node->sub_client = id;
	}

	return;
}



/*	For duplicate node
	TODO*/
void del_node(struct db_node *node)
{
	assert(node);
	log_info("DEL_NODE_START");
	if (node->sub_client || node->down || node->hashtag) {
		log("Node can't be deleted!");
		return;
	}

	if (node->next) {
		log("DELETE NODE AND NEXT!");
		struct db_node *first = node->up->down;
		if (first == node) {
			node->up->plus = false;
			node->up->down = node->next ? node->next : NULL;
		} else {
			while (first->next != node) {
				first = first->next;
			}
			if (first->hashtag) {
				first->hashtag = false;
				first->next = first->next->next;
				del_node(first);
			} else {
				first->next = first->next->next;
			}
		}
		/* delete node */
		delete_db_node(node);
	} else {
		log("DELETE NODE AND UP!");
		if (node->up == NULL) {
			log("Node can't be deleted!");
			return;
		} else if (node->up->next == node) {
			node->up->hashtag = false;
			node->up->next = NULL;
			delete_db_node(node);
			return;
		}

		struct db_node *tmp_node = node->up;
		if (tmp_node->plus && tmp_node->down == node) {
			tmp_node->plus = false;
		}

		if (tmp_node->down == node) {
			tmp_node->down = NULL;
		} else {
			tmp_node = tmp_node->down;
			while (tmp_node->next != node) {
				tmp_node = tmp_node->next;
			}
			if (tmp_node->hashtag) {
				tmp_node->hashtag = false;
				tmp_node->next = tmp_node->next->next;
			} else {
				tmp_node->next = tmp_node->next->next;
			}
		}
		delete_db_node(node);
		/* delete node */
		del_node(tmp_node);

		/* iter */
		/*
		   while (1) {
		// TODO 

		}
		 */
	}
	return;
}


void set_retain_msg(struct db_node *node, struct retain_msg *retain)
{
	node->retain = retain;
}

struct retain_msg *get_retain_msg(struct db_node *node)
{
	return node->retain;
}

/* 
 ** Delete client. 
 */
struct client *del_client(struct topic_and_node *input, char *id)
{
	log_info("DEL_CLIENT_START");
	assert(input && id);
	struct client *client = input->node->sub_client;
	struct client *before_client = NULL;
	while (client) {
		// debug("delete id is %s, client id is %s", id, client->id);
		if (!strcmp(client->id, id)) {
			log("delete client %s", id);
			if (before_client) {
				before_client->next = before_client->next->next;
				return client;
			} else {
				before_client = input->node->sub_client;
				if (input->node->sub_client->next) {
					input->node->sub_client = input->node->sub_client->next;
				} else {
					input->node->sub_client = NULL;
				}

				return client;
			}
		}
		before_client = client;
		client = client->next;
	}
	if (client == NULL) {
		log("no client is deleted!");
	}
	return NULL;
}

bool check_client(struct db_node *node, char *id)
{
	assert(node && id);
	struct client *sub = node->sub_client;
	while (sub) {
		if(!strcmp(sub->id, id)) {
			log("clientID you find is in the tree node");
			return false;
		}

		sub = sub->next;
	}
	return true;
}


struct client *set_client(const char *id, void *ctxt)
{
	assert(id);
	// assert(ctxt);
	struct client *sub_client = NULL;
	sub_client = (struct client*)zmalloc(sizeof(struct client));
	memset(sub_client, 0, sizeof(struct client));
	sub_client->id = (char*)zmalloc(strlen(id)+1);
	memcpy(sub_client->id, id, strlen(id)+1);
	sub_client->ctxt = ctxt;
	// sub_client->next = NULL;
	return sub_client;

}

/* 
 ** Add client. 
 ** Before add_client, you can call set_client to set the val of client
 ** & search_node to get the val of res where you can add_client
 */
void add_client(struct topic_and_node *input, struct client *sub_client)
{
	log_info("ADD_CLIENT_START");
	assert(input && sub_client);

	if (input->node->sub_client == NULL) {
		input->node->sub_client = sub_client;
		log("add first client in this node");
	} else {
		struct client *client = input->node->sub_client;
		if (!strcmp(client->id, sub_client->id)) {
			log("clientID you find is in the tree node");
			return;
		}

		while (client->next) {
			if (strcmp(client->id, sub_client->id)) {
				client = client->next;
			} else {
				log("clientID you find is in the tree node");
				return;
			}
		}
		log("add client %s", sub_client->id);
		client->next = sub_client;
	}
	return;
}

void set_topic_and_node(char **topic_queue, bool hashtag, state t_state,
		struct db_node *node, struct topic_and_node *tan)
{
	tan->t_state = t_state;
	tan->topic = topic_queue;
	tan->hashtag = hashtag;
	tan->node = node;
	return;
}

/* 
 ** search_node
 ** Pass the parameters db_tree and topic_queue, you will get the 
 ** last node equal topic, if topic_queue matches exactly, tan->topic
 ** will be set NULL.
 */

void search_node(struct db_tree *db, char **topic_queue, struct topic_and_node *tan)
{
	log_info("SEARCH_NODE_START");
	assert(db->root && topic_queue);
	struct db_node *node = db->root;

	while (*topic_queue && node){
		log("topic is: %s, node->topic is: %s", *topic_queue, node->topic);
		if (strcmp(node->topic, *topic_queue)) {
			bool equal = false;
			node = find_next(node, &equal, topic_queue);
			if (equal == false) {
				log("searching unqual");
				set_topic_and_node(topic_queue, false, UNEQUAL, node->up, tan);
				break;
			}
		}

		if (node->hashtag && check_hashtag(*(topic_queue+1))) {
			log("searching # with hashtag");
			set_topic_and_node(NULL, true, EQUAL, node->next, tan);
			debug("%s", node->next->sub_client->id);
			break;
		} else if (check_hashtag(*(topic_queue+1))) {
			log("searching # no hashtag");
			set_topic_and_node(topic_queue, true, EQUAL, node, tan);
			break;
		}

		log("searching no hashtag");
		if (node->down && *(topic_queue+1)) {
			// debug("continue");
			topic_queue++;
			node = node->down;
		} else if (*(topic_queue+1) == NULL) {
			// debug("topic_queue is NULL");
			set_topic_and_node(NULL, false, EQUAL, node, tan);
			// debug("node->topic = %s", node->topic);
			break;
		} else {
			// debug("node is NULL");
			set_topic_and_node(topic_queue, false, EQUAL, node, tan);
			break;
		}
	}
	return;
}

void del_all(uint32_t pipe_id, void *ptr)
{
	char *client = get_client_id(pipe_id);
	if (client == NULL) {
		log("no client is found");
		return;
	}
	log("--PID %d--CLID %s--", pipe_id, client);
	struct db_tree *db = ptr;

	if (client) {
		if (check_id(client)) {
			struct topic_queue *tq = get_topic(client);
			while (tq) {
				char **topic_queue = topic_parse(tq->topic);
				struct topic_and_node *tan = NULL;
				tan = (struct topic_and_node*)zmalloc(sizeof(struct topic_and_node));
				search_node(db, topic_queue, tan);
				debug("%s", tan->node->topic);
				del_client(tan, client);
				// struct client * cli = del_client(tan, client);
				// TODO free cli
				// cli = NULL;
				del_node(tan->node);

				char *tmp = NULL;
		 		char **tt = topic_queue;

				while (*topic_queue) {
					tmp = *topic_queue;
					topic_queue++;
					zfree(tmp);
					tmp = NULL;
				}

				zfree(tt);
				topic_queue = NULL;

				zfree(tan);
				tan = NULL;

				tq = tq->next;
			}
			del_topic_all(client);
			del_pipe_id(pipe_id);
			log("del all");
		}  else {
			log("no topic can be found");
		}
	}
	return;
}

void *get_client_info(struct db_node *node)
{
	/* TODO */
	return NULL;

}

struct client **iterate_client(struct clients *sub_clients, int *cols)
{

	*cols = 1;
	struct client **client_queue = NULL;

	while (sub_clients) {
		struct client *sub_client = sub_clients->sub_client;
		while (sub_client) {
			bool equal = false;
			client_queue = (struct client**)zrealloc(client_queue, (*cols)*sizeof(struct client*)); 

			for (int i = 0; i < (*cols)-1; i++) {
				if (!strcmp(sub_client->id, client_queue[i]->id)) {
					equal = true;
					break;
				}
			}

			if (equal == false) {
				client_queue[(*cols)-1] = sub_client;
				(*cols)++;
			}
			sub_client = sub_client->next;
		}
		sub_clients = sub_clients->down;
	}

	client_queue = (struct client**)zrealloc(client_queue, (*cols) * sizeof(struct client*)); 
	client_queue[(*cols)-1] = NULL;
	return client_queue;
}

struct clients *new_clients(struct client *sub_client)
{
	struct clients *sub_clients = NULL;
	if (sub_client) {
		sub_clients = (struct clients*)zmalloc(sizeof(struct clients));
		sub_clients->sub_client = sub_client;
		sub_clients->down = NULL;
		debug("first client is %s", sub_clients->sub_client->id);
	}
	return sub_clients;
}

struct db_node *find_next(struct db_node *node, bool *equal, char **topic_queue)
{
	struct db_node  *t = node;

	if (node == NULL) {
		return NULL;
	}

	while (t->next) {
		t = t->next;
		log("t->topic %s, topic_queue %s", t->topic,
							*(topic_queue));
		if (!strcmp(t->topic, *(topic_queue))) {
			*equal = true;
			break;
		}
	}
	return t;
}


/*
 ** search_client
 ** When you use this func, the parameters you need to pass are the root 
 ** node of the tree and the complete topic_queue. You will get all the 
 ** subscribers to this topic.
 */
struct clients *search_client(struct db_node *root, char **topic_queue)
{
	log_info("SEARCH_CLIENT_START");
	assert(root && topic_queue);
	struct clients *res = NULL;
	struct clients *tmp = NULL;
	tmp = (struct clients*)zmalloc(sizeof(struct clients));
	memset(tmp, 0, sizeof(struct clients));
	res = tmp;
	struct db_node *node = root;

	log("entry search");
	while (*topic_queue && node) {
		if (strcmp(node->topic, *topic_queue)) {
			log("node->topic %s, topic_queue %s", node->topic, *topic_queue);

			bool plus = false;
			if (!strcmp(node->topic, "+")) {
				if (*(topic_queue+1) == NULL) {
					if (node->sub_client) {
						log("add client in last +");
						tmp->down = new_clients(node->sub_client);
						tmp = tmp->down;
					}
				} else {
					plus = true;
					if (node->hashtag) {
						log("Find the sign of #. Add it if sub_client is exist");
						if (node->next->sub_client) {
							tmp->down = new_clients(node->next->sub_client);
							tmp = tmp->down;
						}
					}
				}  
			}

			bool equal = false;
			node = find_next(node, &equal, topic_queue);

			if (equal == false && plus == false) {
				log("searching unqual");
				return res;
			}

			if (equal == false && plus == true) {
				node = node->up->down;
			}
		}

		if (node->hashtag) {
			log("Find the sign of #. Add it if sub_client of # is exist!");
			if (node->next->sub_client) {
				tmp->down = new_clients(node->next->sub_client);
				tmp = tmp->down;
			}
		}

		if (*(topic_queue+1) == NULL) {
			log("Current node is the last one. Add it if sub_client is exist!");
			tmp->down = new_clients(node->sub_client);
			tmp = tmp->down;
			return res;
		}

		
		if (node->plus) { 
			log("Find the sign of +");
			if (*(topic_queue+2) == NULL) {
				debug("When plus is the last one");
				if (node->down->hashtag) {
					log("Find the sign of #. Add it if sub_client of # is exist!");
					if (node->down->next->sub_client) {
						tmp->down = new_clients(node->down->next->sub_client);
						tmp = tmp->down;
					}
				}

				if (node->down->sub_client) {
					tmp->down = new_clients(node->down->sub_client);
					tmp = tmp->down;
				}

				bool equal = false;
				struct db_node  *t = find_next(node->down, &equal,
						++topic_queue);

				if (equal == false) {
					log("searching unqual");
					return res;
				}

				if (t->hashtag) {
					log("Find the sign of #. Add it if sub_client of # is exist!");
					if (t->next->sub_client) {
						tmp->down = new_clients(t->next->sub_client);
						tmp = tmp->down;
					}
				}


                if (t->sub_client) {
					tmp->down = new_clients(t->sub_client);
					tmp = tmp->down;
				}
				return res;

			} else if (node->down->down == NULL) {
				log("topic is longer than tree, check hashtag");

				if (node->down->hashtag) {
					log("Find the sign of #. Add it if sub_client of # is exist!");
					if (node->down->next->sub_client) {
						tmp->down = new_clients(node->down->next->sub_client);
						tmp = tmp->down;
					}
				}

				bool equal = false;
				struct db_node  *t = find_next(node->down, &equal,
						++topic_queue);

				if (equal == false) {
					log("searching unqual");
					return res;
				}

				if (t->hashtag) {
					log("Find the sign of #. Add it if sub_client of # is exist!");
					if (t->next->sub_client) {
						tmp->down = new_clients(t->next->sub_client);
						tmp = tmp->down;
					}
				}

				if (t != node->down) {
					log("t->topic, %s, topic_queue ,%s", t->topic,
							*(topic_queue));
					tmp->down = search_client(t, topic_queue);
				}
				return res;

			} else if (node->down->down && *(topic_queue+2)) {
				log("continue");
				char ** tmp_topic = topic_queue;
				tmp->down = search_client(node->down, topic_queue+1);
				while (tmp->down) {
					tmp = tmp->down;
				}
				tmp->down = search_client(node->down->down, tmp_topic+2);
				return res;
			}

		} else {
			log("Find node no sign of + & #");
			if (node->down && *(topic_queue+1)) {
				log("continue");
				topic_queue++;
				node = node->down;

			} else {
				return res;
			}
		}
	}

	return res;
}

/* topic parsing */
char **topic_parse(char *topic)
{
	assert(topic != NULL);

	int row = 1;
	int len = 2;
	char **topic_queue = NULL;
	char *before_pos = topic;
	char *pos = NULL;

	if ((strncmp("$share", before_pos, 6) != 0 && strncmp("$SYS", before_pos, 4)
				!= 0)) {
		topic_queue = (char**)zmalloc(sizeof(char*)*row);
		topic_queue[row-1] = (char*)zmalloc(sizeof(char)*len);
		memcpy(topic_queue[row-1], "\0", (len));
		// strcpy(topic_queue[row-1], "");
		//	topic_queue[0][0] = '';
		//	topic_queue[row-1][len-1] = '\0';

	}

	while ((pos = strchr(before_pos, '/')) != NULL) {

		if (topic_queue != NULL) {
			topic_queue = (char**)zrealloc(topic_queue, sizeof(char*)*(++row));
		} else {
			topic_queue = (char**)zmalloc(sizeof(char*)*row);
		}


		len = pos-before_pos+1;
		topic_queue[row-1] = (char*)zmalloc(sizeof(char)*len);
		memcpy(topic_queue[row-1], before_pos, (len-1));
		topic_queue[row-1][len-1] = '\0';
		before_pos = pos+1;
	}

	len = strlen(before_pos);

	if (topic_queue != NULL) {
		topic_queue = (char**)zrealloc(topic_queue, sizeof(char*)*(++row));
	} else {
		topic_queue = (char**)zmalloc(sizeof(char*)*row);
	}

	topic_queue[row-1] = (char*)zmalloc(sizeof(char)*(len+1));
	// strcpy(topic_queue[row-1], before_pos);
	memcpy(topic_queue[row-1], before_pos, (len));
	topic_queue[row-1][len] = '\0';
	topic_queue = (char**)zrealloc(topic_queue, sizeof(char*)*(++row));
	topic_queue[row-1] = NULL;

	return topic_queue;
}

void hash_add_alias(int alias, char *topic_data)
{
	assert(topic_data);
	push_val(alias, topic_data);
}

char *hash_check_alias(int alias)
{
	return get_val(alias);
}

void hash_del_alias(int alias)
{
	del_val(alias);
}

