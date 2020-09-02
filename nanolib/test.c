#include <string.h>
#include "include/nanolib.h"


// struct clientId ID = {"150410"};
// struct db_node node = {"", &ID, NULL, NULL, NULL, NULL, 1, -1};  
// struct db_tree db = {&node};

struct db_tree *db = NULL;

typedef enum{test_topic_parse = 0, test_search_node, test_add_node, test_del_node,
	test_hash_alias, test_topic_hash, test_pipe_hash} test_state;

struct client ID1 = {"150429", NULL, NULL};

static void Test_topic_parse(void)
{
	puts(">>>>>>>>>> TEST_TOPIC_PARSE <<<<<<<<");
	// char *data = NULL;
	// char *data = "lee";
	// char *data = "$share/hom/jian";
	char *data = "$shar/hom/jian";
	printf("INPUT:%s\n", data);

	char **res = topic_parse(data);
	char *t = NULL;
	char **tt = res;


	while (*res) {
		t = *res;
		printf("RES: %s\n", *res);
		res++;
		zfree(t);
		t = NULL;
	}

	zfree(tt);
	res = NULL;
}

static void Test_search_node(void)
{
	puts(">>>>>>>>>> TEST_SEARCH_NODE <<<<<<<<");
	// char *data = "lee";
	char *data = "lee/hom/jian";

	create_db_tree(&db);
	print_db_tree(db);
	struct topic_and_node *res = NULL;
	res = (struct topic_and_node*)zmalloc(sizeof(struct topic_and_node));
	char **topic_queue = topic_parse(data);
	search_node(db, topic_queue, res);

	if (res->topic) {
		printf("RES_TOPIC: %s\n", *(res)->topic);
	}
	if (res->node) {
		printf("RES_NODE_STATE: %d\n", res->t_state);
	}
	if (res->node->sub_client) {
		printf("RES_NODE_UP_ID: %s\n", res->node->sub_client->id);
	}
	zfree(res);
}

static void Test_add_node(void)
{
	puts(">>>>>>>>>>> TEST_ADD_NODE <<<<<<<<<");
	char *data = "a/bv/cv";
	char *data1 = "a/b/c";
	char *data2 = "lee/+/+";
	char *data3 = "lee/hom/+";
	struct client ID3 = {"150410", NULL, NULL};
	struct client ID4 = {"150422", NULL, NULL};
	struct client ID5 = {"150418", NULL, NULL};


	struct topic_and_node *res = NULL;
	res = (struct topic_and_node*)zmalloc(sizeof(struct topic_and_node));
	char **topic_queue = topic_parse(data);

	search_node(db, topic_queue, res);
	add_node(res, &ID1);
	print_db_tree(db);

	search_node(db, topic_queue, res);
	add_node(res, &ID1);
	search_node(db, topic_queue, res);
	if (check_client(res->node, ID1.id)) {
		add_client(res, &ID1);
	} else {
		puts("2@@@@@@@@@@@@@@@@@@@@@@@@@@###@@@@@@@");
	}
	print_db_tree(db);
	printf("RES_NODE_ID: %s\n", res->node->sub_client->id);
	printf("RES_NODE_STATE: %d\n", res->t_state);
	if (res->topic) {
		printf("RES_TOPIC: %s\n", *(res->topic));
	}

	topic_queue = topic_parse(data1);
	search_node(db, topic_queue, res);
	add_node(res, &ID3);
	print_db_tree(db);
	search_node(db, topic_queue, res);
	printf("RES_NODE_ID: %s\n", res->node->sub_client->id);
	printf("RES_NODE_STATE: %d\n", res->t_state);
	if (res->topic) {
		printf("RES_TOPIC: %s\n", *(res->topic));
	}

	topic_queue = topic_parse(data2);
	search_node(db, topic_queue, res);
	add_node(res, &ID4);
	print_db_tree(db);

	search_node(db, topic_queue, res);
	printf("RES_NODE_ID: %s\n", res->node->sub_client->id);
	printf("RES_NODE_STATE: %d\n", res->t_state);
	if (res->topic) {
		printf("RES_TOPIC: %s\n", *(res->topic));
	}

	topic_queue = topic_parse(data3);
	search_node(db, topic_queue, res);
	if (res->topic) {
		add_node(res, &ID5);
	} else {
		if (check_client(res->node, ID5.id)) {
			 add_client(res, &ID5);
		}
	}
	print_db_tree(db);

	search_node(db, topic_queue, res);
	printf("RES_NODE_ID: %s\n", res->node->sub_client->id);
	printf("RES_NODE_STATE: %d\n", res->t_state);
	if (res->topic) {
		printf("RES_TOPIC: %s\n", *(res->topic));
	}
}

static void Test_del_node(void)
{
	puts(">>>>>>>>>> TEST_DEL_NODE <<<<<<<<");
	char *data = "lee/hom/jian/ll";
	char *data1 = "+/#";
	char *data2 = "+/+/+/+";
	struct topic_and_node *res = NULL;
	char **topic_queue = topic_parse(data);
	res = (struct topic_and_node*)zmalloc(sizeof(struct topic_and_node));
	search_node(db, topic_queue, res);

	struct client ID2 = {"150410", NULL, NULL};
	add_node(res, &ID2);
	print_db_tree(db);


	topic_queue = topic_parse(data1);
	search_node(db, topic_queue, res);
	add_node(res, &ID2);
	print_db_tree(db);

	topic_queue = topic_parse(data2);
	search_node(db, topic_queue, res);
	add_node(res, &ID2);
	print_db_tree(db);

	struct clients *res_clients = NULL;
	struct client  **client_queue = NULL;
	int cols = 0;
	topic_queue = topic_parse(data);
	res_clients = search_client(db->root, topic_queue);
	client_queue = iterate_client(res_clients, &cols);

    while ((*client_queue) != NULL) {
			puts("&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&");
			printf("%p %p \n", client_queue, *client_queue);
			printf("RES: client_queue is:%s\n", (*client_queue)->id);
			client_queue++;
	}


	// for (int i = 0; i < cols-1; i++) {
	// 		puts("&&&&&&&&&&&&&&&&&&&&&&&&&&&&&ssss&&&&&&");
	// 		printf("RES: client_queue is:%s\n", client_queue[i]->id);
	// }

		
	puts("----------------------------------------------------\nall:");
	while (res_clients) {
		struct client *sub_client = res_clients->sub_client;
		while (sub_client) {
			printf("RES: sub_client is:%s\n", sub_client->id);
			sub_client = sub_client->next;
		}
		res_clients = res_clients->down;
	}

	// search_node(db, topic_queue, res); 
	// del_client(res, ID2.id);
	// print_db_tree(db);

	// del_node(res->node);
	// print_db_tree(db);

	// topic_queue = topic_parse(data1);
	// search_node(db, topic_queue, res); 
	// del_client(res, ID2.id);
	// print_db_tree(db);
	// del_node(res->node);
	// print_db_tree(db);

	// topic_queue = topic_parse(data2);
	// search_node(db, topic_queue, res); 
	// del_client(res, ID2.id);
	// print_db_tree(db);
	// del_node(res->node);
	// print_db_tree(db);
}

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

void test(test_state what) 
{
	switch(what) {
		case test_topic_parse:
			Test_topic_parse();
			break;
		case test_search_node:
			Test_search_node();
			break;
		case test_add_node:
			Test_add_node();
			break;
		case test_del_node:
			Test_del_node();
			break;
		case test_hash_alias:
			Test_hash_alias();
			break;
		case test_topic_hash:
			Test_topic_hash();
			break;
		case test_pipe_hash:
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
	printf(" test_topic_parse,  0\n");
	printf(" test_search_node,  1\n");
	printf(" test_add_node,     2\n");
	printf(" test_del_node,	    3\n");
	printf(" test_hash_alias,   4\n");
	printf(" test_topic_hash,   5\n");
	printf(" test_pipe_hash,    6\n");
	printf(" quit               q\n");
	printf(" help               h\n");
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
		test((test_state)i);
	}

	int i = 2;
	puts("11111");
	print_db_tree(db);
	del_all(i, db);
	puts("22222");
	print_db_tree(db);
	puts("---------------TEST FINISHED----------------\n");
	return 0;
}

