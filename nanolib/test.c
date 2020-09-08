#include <string.h>
#include "include/nanolib.h"



typedef enum{	
	TEST_TOPIC_PARSE = 0, 
	TEST_SEARCH_NODE, 
	TEST_ADD_NODE, 
	TEST_DEL_NODE,
	TEST_ADD_CLIENT, 
	TEST_DEL_CLIENT, 
	TEST_SEARCH_CLIENT, 
	TEST_RETAIN_MSG, 
	TEST_HASH_ALIAS, 
	TEST_TOPIC_HASH, 
	TEST_PIPE_HASH 
} TEST_STATE;


struct db_tree *db = NULL;

const int len = 9;
char* data[] = {
	"a/bv/cv", 
	"$zhang/bei/hai", 
    "$zhang/bei/hai/ll",
    "+/+/+/+",        
	"a/b/c", 
	"a/b/#", 
	"a/+/+", 
	"a/+/c",
    "+/#",            
	"#" 
};

struct client ID[] = { 
	{"150429", NULL, NULL}, 
    {"150410", NULL, NULL},
    {"150422", NULL, NULL},
    {"150418", NULL, NULL},
    {"150666", NULL, NULL},
    {"130429", NULL, NULL},
    {"130410", NULL, NULL},
    {"130422", NULL, NULL},
    {"130418", NULL, NULL},
    {"666666", NULL, NULL}
};


static void Test_topic_parse(void)
{
	puts(">>>>>>>>>> TEST_TOPIC_PARSE <<<<<<<<");

	int index = 0;
	while (index < len) {
		printf("INPUT:%s\n", data[index]);
		char **res = topic_parse(data[index]);
		char **t = res;

		printf("OUTPUT: ");
		while (*t) {
			printf("%s ", *t);
			t++;
		}
		printf("\n");
		free_topic_queue(res);
		index++;
	}
}

static void Test_search_node(void)
{
	puts(">>>>>>>>>> TEST_SEARCH_NODE <<<<<<<<");

	print_db_tree(db);

	int index = 0;
	while (index < len) {
		printf("INPUT:%s\n", data[index]);
		struct topic_and_node res;
		memset(&res, 0, sizeof(struct topic_and_node));

		char **topic_queue = topic_parse(data[index]);

		search_node(db, topic_queue, &res);

		if (res.topic != NULL) {
			printf("RES_TOPIC: %s\n", *(res.topic));
		}
		if (res.node) {
			printf("RES_NODE_STATE: %d\n", res.t_state);
		}
		if (res.node->sub_client) {
			printf("RES_NODE_UP_ID: %s\n", res.node->sub_client->id);
		}

		free_topic_queue(topic_queue);
		index++;
	}
}

static void Test_add_node(void)
{
	puts(">>>>>>>>>>> TEST_ADD_NODE <<<<<<<<<");

	print_db_tree(db);

	int index = 0;
	while (index < len) {
		printf("INPUT:%s\n", data[index]);
		struct topic_and_node res;
		memset(&res, 0, sizeof(struct topic_and_node));

		char **topic_queue = topic_parse(data[index]);

		search_node(db, topic_queue, &res);
		add_node(&res, &ID[index]);
		print_db_tree(db);

		free_topic_queue(topic_queue);
		index++;
	}


}

static void Test_del_node(void)
{
	puts(">>>>>>>>>> TEST_DEL_NODE <<<<<<<<");

	int index = 0;
	while (index < len) {
		printf("INPUT:%s\n", data[index]);
		struct topic_and_node res;
		memset(&res, 0, sizeof(struct topic_and_node));

		char **topic_queue = topic_parse(data[index]);

		search_node(db, topic_queue, &res);
		log("@@@@@@@@@@@@@@");
		del_client(&res, ID[index].id);
		del_node(res.node);
		print_db_tree(db);

		free_topic_queue(topic_queue);
		index++;
	}

}

static void Test_add_client()
{
	int index = 0;
	while (index < len) {
		printf("INPUT:%s\n", data[index]);
		struct topic_and_node res;
		memset(&res, 0, sizeof(struct topic_and_node));

		char **topic_queue = topic_parse(data[index]);

		search_node(db, topic_queue, &res);
		add_client(&res, &ID[index]);
		print_db_tree(db);

		free_topic_queue(topic_queue);
		index++;
	}


}

static void Test_del_client()
{
	int index = 0;
	while (index < len) {
		printf("INPUT:%s\n", data[index]);
		struct topic_and_node res;
		memset(&res, 0, sizeof(struct topic_and_node));

		char **topic_queue = topic_parse(data[index]);

		search_node(db, topic_queue, &res);
		del_client(&res, ID[index].id);
		print_db_tree(db);

		free_topic_queue(topic_queue);
		index++;
	}
}

static void Test_search_client() 
{
	int index = 0;
	while (index < len) {
		printf("INPUT:%s\n", data[index]);
		struct topic_and_node res;
		memset(&res, 0, sizeof(struct topic_and_node));

		int cols = 0;
		char **topic_queue = NULL;
		struct clients *res_clients = NULL;
		struct client  **client_queue = NULL;


		print_db_tree(db);
		topic_queue = topic_parse(data[index]);
		res_clients = search_client(db->root, topic_queue);
		client_queue = iterate_client(res_clients, &cols);

		while ((*client_queue) != NULL) {
				puts("&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&");
				printf("%p %p \n", client_queue, *client_queue);
				printf("RES: client_queue is:%s\n", (*client_queue)->id);
				client_queue++;
		}
		
		zfree(client_queue);
		client_queue = NULL;

		puts("----------------------------------------------------\nall:");
		struct clients *for_free = res_clients;
		while (res_clients) {
			struct client *sub_client = res_clients->sub_client;
			while (sub_client) {
				printf("RES: sub_client is:%s\n", sub_client->id);
				sub_client = sub_client->next;
			}
			res_clients = res_clients->down;
		}

		while (for_free) {
			log("@@@@@@@@@@@@for free");
			struct clients *tt = for_free;
			for_free = for_free->down;
			zfree(tt);
			tt = NULL;
		}

		free_topic_queue(topic_queue);
		index++;
	}
}

static void Test_retain_msg() {

	int index = 0;
	struct retain_msg_node *msg_node = NULL;
	struct retain_msg * set_msg = NULL;

	while (index < len) {
		printf("INPUT:%s\n", data[index]);
		struct topic_and_node res; 
		memset(&res, 0, sizeof(struct topic_and_node));
		char **topic_queue = topic_parse(data[index]);

		set_msg = (struct retain_msg*)zmalloc(sizeof(struct retain_msg));
		memset(set_msg, 1, sizeof(struct retain_msg));

		search_node(db, topic_queue, &res);

		if (res.topic) {
			add_node(&res, NULL);
		}

		set_retain_msg(res.node, set_msg);
		// print_db_tree(db);
		log(" Test retain_msg");

		free_topic_queue(topic_queue);
		index++;
	}

	index = 0;
	while (index < len) {
		printf("INPUT:%s\n", data[index]);

		print_db_tree(db);
		char **topic_queue = topic_parse(data[index]);
		msg_node = search_retain_msg(db->root, topic_queue); 
		struct retain_msg_node *for_free = msg_node;
		log(" Test return");
		while (msg_node->down) {
			log("###################");
			log("ret_msg: %p", msg_node->down->ret_msg);
			msg_node = msg_node->down;
		}
		free_retain_node(for_free);

		free_topic_queue(topic_queue);
		index++;
	}


}

	// search_node(db, topic_queue, res);
	// add_node(res, &ID1);
	// search_node(db, topic_queue, res);
	// if (check_client(res->node, ID1.id)) {
	// 	add_client(res, &ID1);
	// } else {
	// 	puts("2@@@@@@@@@@@@@@@@@@@@@@@@@@###@@@@@@@");
	// }
	// print_db_tree(db);
	// printf("RES_NODE_ID: %s\n", res->node->sub_client->id);
	// printf("RES_NODE_STATE: %d\n", res->t_state);
	// if (res->topic) {
	// 	printf("RES_TOPIC: %s\n", *(res->topic));
	// }


	// topic_queue = topic_parse(data3);
	// search_node(db, topic_queue, res);
	// if (res->topic) {
	// 	add_node(res, &ID5);
	// } else {
	// 	if (check_client(res->node, ID5.id)) {
	// 		 add_client(res, &ID5);
	// 	}
	// }
	// print_db_tree(db);


static void Test_hash_alias(void) 
{
	puts(">>>>>>>>>>TEST_HASH_TABLE<<<<<<<<");
	int i = 1;
	int j = 2;
	int k = 3;
	char *topic1 = "topic1";
	char *topic2 = "topic2";
	char *topic3 = "topic3";
	printf("INPUT: %d --> %s\n", i, topic1);
	printf("INPUT: %d --> %s\n", j, topic2);
	printf("INPUT: %d --> %s\n", k, topic3);


	hash_add_alias(i, topic1);
	hash_add_alias(i, topic2);
	hash_add_alias(i, topic3);
	hash_add_alias(j, topic2);
	hash_add_alias(k, topic3);
	char* t1 = hash_check_alias(i);
	char* t2 = hash_check_alias(j);
	char* t3 = hash_check_alias(k);

	printf("RES: %s\n", t1);
	printf("RES: %s\n", t2);
	printf("RES: %s\n", t3);
	hash_del_alias(i);
	hash_del_alias(j);
	hash_del_alias(k);
	t1 = hash_check_alias(i);
	t2 = hash_check_alias(j);
	t3 = hash_check_alias(k);
	if (t1) {
		printf("RES: %s\n", t1);
	}

	if (t2) {
		printf("RES: %s\n", t2);
	}

	if (t3) {
		printf("RES: %s\n", t3);
	}

}

static void Test_topic_hash(void) 
{
	char *id = "150410";
	char *val = "lee/hom/jian";
	char *val1 =  "#";          
	char *val2 =  "lee/#";      
	char *val3 = "a/b/c";

	if (check_id(id)) {
		puts("find");
	} else {
		puts("not find");
	}
	add_topic(id, val);
	add_topic(id, val1);
	add_topic(id, val2);
	add_topic(id, val3);
	
	if (check_id(id)) {
		puts("find");
	} else {
		puts("not find");
	}

	struct topic_queue *res = get_topic(id); 
	while (res) {
		printf("res: %s\n", res->topic);
		res = res->next;
	}

	// del_topic_one(id, val1);
	res = get_topic(id); 
	while (res) {
		printf("res: %s\n", res->topic);
		res = res->next;
	}
	// del_topic_all(id);

	if (check_id(id)) {
		puts("find");
	} else {
		puts("not find");
	}
}

static void Test_pipe_hash(void)
{
	uint32_t pipeid[] = {1, 2, 3, 4};
	char* clientid[] ={"150429", "150410", "150428", "150418"};
	for (int i = 0; i < 4; i++) {
		add_pipe_id(pipeid[i], clientid[i]);
		printf("get_client_id %s\n", get_client_id(pipeid[i]));
		// del_pipe_id(pipeid[i]);
	}
}






void test(TEST_STATE WHAT) 
{
	switch(WHAT) {
		case TEST_TOPIC_PARSE:
			Test_topic_parse();
			break;
		case TEST_SEARCH_NODE:
			Test_search_node();
			break;
		case TEST_ADD_NODE:
			Test_add_node();
			break;
		case TEST_DEL_NODE:
			Test_del_node();
			break;
		case TEST_ADD_CLIENT:
			Test_add_client();
			break;
		case TEST_DEL_CLIENT:
			Test_del_client();
			break;
		case TEST_SEARCH_CLIENT:
			Test_search_client();
			break;
		case TEST_RETAIN_MSG:
			Test_retain_msg();
			break;
		case TEST_HASH_ALIAS:
			Test_hash_alias();
			break;
		case TEST_TOPIC_HASH:
			Test_topic_hash();
			break;
		case TEST_PIPE_HASH:
			Test_pipe_hash();
			break;
		default:
			log("No this state");
			break;
	}
			
}

void help() 
{
	printf("please input the right num to conduct diff test\n");
	printf(" test_topic_parse,      0\n");
	printf(" test_search_node,      1\n");
	printf(" test_add_node,         2\n");
	printf(" test_del_node,	        3\n");
	printf(" test_add_client,       4\n");
	printf(" test_del_client,       5\n");
	printf(" test_search_client,    6\n");
	printf(" test_retain_msg,       7\n");
	printf(" test_hash_alias,       8\n");
	printf(" test_topic_hash,       9\n");
	printf(" test_pipe_hash,       10\n");
	printf(" quit                   q\n");
	printf(" help                   h\n");
}



int main(int argc, char *argv[]) 
{
	puts("\n----------------TEST START------------------");
	char str[5];
	create_db_tree(&db);
	help();

	while (1) {
		printf("input:");
		scanf("%s", str);
		if (!strcmp(str, "q")) {
			break;
		} else if (!strcmp(str, "h")) {
			help();
			continue;
		}

		int i = atoi(str);
		test((TEST_STATE)i);
	}

	// int i = 2;
	// print_db_tree(db);
	// del_all(i, db);
	// print_db_tree(db);
	destory_db_tree(db);
	puts("---------------TEST FINISHED----------------\n");
	return 0;
}

