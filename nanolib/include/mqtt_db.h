#ifndef MQTT_DB_H
#define MQTT_DB_H

#include <stdbool.h>
#include <stdint.h>

typedef enum {UNEQUAL = 0, EQUAL = 1 } state;


struct client {
	char				*id;
	void			    *ctxt;
	struct client		*next;
};

struct clients {
	struct client*		sub_client;
	struct clients*		down;
	int					len;
};

struct retain_msg_node {
	struct retain_msg		*ret_msg;
	struct retain_msg_node	*down;
};

struct retain_msg {
	uint8_t				qos;
	bool				exist;
	void				*message;
};

struct db_node {
	char                *topic;
	bool				hashtag;
	bool				plus;
	struct retain_msg   *retain;
	struct client		*sub_client;
	struct db_node      *up;
	struct db_node      *down;
	struct db_node      *next;
};

/* 
** for print_db_tree 
*/

struct db_nodes {
	struct db_node		*node;
	struct db_nodes		*next;
};

/* if topic equal NULL, topic is finded */ 
struct topic_and_node {
	char				**topic;
	bool				hashtag;
	struct db_node		*node; 
	state				t_state;
};

struct db_tree{
	struct db_node      *root;
	// TODO
};



/* Create a db_tree */
void create_db_tree(struct db_tree **db);

/* Delete a db_tree */
void destory_db_tree(struct db_tree *db);

void print_db_tree(struct db_tree *db);

bool check_hashtag(char *topic_data);

bool check_plus(char *topic_data); 

struct db_node *new_db_node(char *topic);

void delete_db_node(struct db_node *node);

void set_db_node(struct db_node *node, char **topic_queue);

/* Search node in db_tree*/
void search_node(struct db_tree *db, char **topic_queue, struct topic_and_node *tan);

/* Add node to db_tree */
void add_node(struct topic_and_node *input, struct client *id);

/* Delete node from db_tree when node does not have clientId */
void del_node(struct db_node *node);

void del_all(uint32_t pipe_id, void *db);

/* Free node memory */
void free_node(struct db_node *node);

/* Parsing topic from char* with '/' to char** */
char **topic_parse(char *topic);

void free_topic_queue(char **topic_queue);

struct db_node *find_next(struct db_node *node, bool *equal, char
		**topic_queue);

void set_retain_msg(struct db_node *node, struct retain_msg *retain);

struct retain_msg *get_retain_msg(struct db_node *node);

struct retain_msg_node *search_retain_msg(struct db_node *root, 
		char **topic_queue); 

void free_retain_node(struct retain_msg_node *msg_node);

struct clients *search_client(struct db_node *root, char **topic_queue);

bool check_client(struct db_node *node, char *id);

/* Delete client id. */
struct client *del_client(struct topic_and_node *input, char *id);

struct client *set_client(const char *id, void *ctxt); 

void set_topic_and_node(char **topic_queue, bool hashtag, state t_state, 
		struct db_node *node, struct topic_and_node *tan);

struct client **iterate_client(struct clients * sub_clients, int *cols); 

struct clients *new_clients(struct client *sub_client);

/* Add client id. */
void add_client(struct topic_and_node *input, struct client* sub_client);

/* A hash table, clientId or alias as key, topic as value */ 
char* hash_check_alias(int alias);

void hash_add_alias(int alias, char *topic_data);

void hash_del_alias(int alias);

#endif
