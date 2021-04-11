#include "include/nanolib.h"
#include <string.h>

#define NUM_THREADS 8

db_tree *db     = NULL;
db_tree *db_ret = NULL;

///////////for wildcard////////////
char topic0[] = "zhang/bei/hai";
char topic1[] = "zhang/#";
char topic2[] = "#";
char topic3[] = "zhang/bei/#";
char topic4[] = "zhang/+/hai";
char topic5[] = "zhang/bei/+";
char topic6[] = "zhang/bei/h/ai";
char topic7[] = "+/+/+";
char topic8[] = "zhang/+/+";
char topic9[] = "zhang/bei/hai";

//////////for binary_search/////////
char topic00[] = "zhang/bei/hai";
char topic01[] = "zhang/bei/aih";
char topic02[] = "zhang/bei/iah";
char topic03[] = "zhang/ee/aa";
char topic04[] = "zhang/ee/bb";
char topic05[] = "zhang/ee/cc";
char topic06[] = "aa/xx/yy";
char topic07[] = "bb/zz/aa";
char topic08[] = "cc/dd/aa";
char topic09[] = "www/xxx/zz";

////////////////////////////////////
s_client client0 = { 150429, NULL };
s_client client1 = { 150428, NULL };
s_client client2 = { 150427, NULL };
s_client client3 = { 150426, NULL };
s_client client4 = { 150425, NULL };
s_client client5 = { 150424, NULL };
s_client client6 = { 150423, NULL };
s_client client7 = { 150422, NULL };
s_client client8 = { 150421, NULL };
s_client client9 = { 150420, NULL };

retain_msg retain0 = { 1, true, "150429", NULL };
retain_msg retain1 = { 1, true, "150428", NULL };
retain_msg retain2 = { 1, true, "150427", NULL };
retain_msg retain3 = { 1, true, "150426", NULL };
retain_msg retain4 = { 1, true, "150425", NULL };
retain_msg retain5 = { 1, true, "150424", NULL };
retain_msg retain6 = { 1, true, "150423", NULL };
retain_msg retain7 = { 1, true, "150422", NULL };
retain_msg retain8 = { 1, true, "150421", NULL };
retain_msg retain9 = { 1, true, "150420", NULL };

s_client client[] = {
	{ 150429, NULL },
	{ 150428, NULL },
	{ 150427, NULL },
	{ 150426, NULL },
	{ 150425, NULL },
	{ 150424, NULL },
	{ 150423, NULL },
	{ 150422, NULL },
	{ 150421, NULL },
	{ 150420, NULL },
};

char id[] = "hahahha";

static void
test_insert()
{
	search_and_insert(db, topic0, id, NULL, client0.pipe_id);
	print_db_tree(db);
	search_and_insert(db, topic1, id, NULL, client1.pipe_id);
	print_db_tree(db);
	search_and_insert(db, topic2, id, NULL, client2.pipe_id);
	print_db_tree(db);
	search_and_insert(db, topic3, id, NULL, client3.pipe_id);
	print_db_tree(db);
	search_and_insert(db, topic4, id, NULL, client4.pipe_id);
	print_db_tree(db);
	search_and_insert(db, topic5, id, NULL, client5.pipe_id);
	print_db_tree(db);
	search_and_insert(db, topic6, id, NULL, client6.pipe_id);
	print_db_tree(db);
	search_and_insert(db, topic7, id, NULL, client7.pipe_id);
	print_db_tree(db);
	search_and_insert(db, topic8, id, NULL, client8.pipe_id);
	print_db_tree(db);
	search_and_insert(db, topic9, id, NULL, client9.pipe_id);
	print_db_tree(db);

	// client0.id = "150428";
	// client1.id = "150427";
	// client2.id = "150426";
	// client3.id = "150425";
	// client4.id = "150424";
	// client5.id = "150425";
	// client6.id = "150426";
	// client7.id = "150427";
	// client8.id = "150428";
	// client9.id = "150429";

	// ///////////////////////////////////////
	// search_and_insert(db, topic0, &client0);
	// print_db_tree(db);
	// search_and_insert(db, topic1, &client1);
	// print_db_tree(db);
	// search_and_insert(db, topic2, &client2);
	// print_db_tree(db);
	// search_and_insert(db, topic3, &client3);
	// print_db_tree(db);
	// search_and_insert(db, topic4, &client4);
	// print_db_tree(db);
	// search_and_insert(db, topic5, &client5);
	// print_db_tree(db);
	// search_and_insert(db, topic6, &client6);
	// print_db_tree(db);
	// search_and_insert(db, topic7, &client7);
	// print_db_tree(db);
	// search_and_insert(db, topic8, &client8);
	// print_db_tree(db);
	// search_and_insert(db, topic9, &client9);
	// //////////////////////////////////////
}

static void
test_delete()
{
	puts("================begin delete===============");
	search_and_delete(db, topic0, client0.pipe_id);
	print_db_tree(db);
	search_and_delete(db, topic1, client1.pipe_id);
	print_db_tree(db);
	search_and_delete(db, topic2, client2.pipe_id);
	print_db_tree(db);
	search_and_delete(db, topic3, client3.pipe_id);
	print_db_tree(db);
	search_and_delete(db, topic4, client4.pipe_id);
	print_db_tree(db);
	search_and_delete(db, topic5, client5.pipe_id);
	print_db_tree(db);
	search_and_delete(db, topic6, client6.pipe_id);
	print_db_tree(db);
	search_and_delete(db, topic7, client7.pipe_id);
	print_db_tree(db);
	search_and_delete(db, topic8, client8.pipe_id);
	print_db_tree(db);
	search_and_delete(db, topic9, client9.pipe_id);
	print_db_tree(db);
}

// static void test_search_client()
// {
//         cvector(s_client*) v =  NULL;
//         v = search_client(db, topic0);
//
//         puts("================Return client==============");
//         if (v) {
//                 for (int i = 0; i < cvector_size(v); ++i) {
//                         log("client id: %s", v[i]->id);
//                 }
//         }
//
//         // if (v) {
//         // 	for (int i = 0; i < cvector_size(v); ++i) {
//         //                 for (int j = 0; j < cvector_size(v[i]); j++) {
//         //                         log("client id: %s", v[i][j]->id);
//         //                 }
//         //         }
//
//         // }
//
//
//
// }

static void *
test_unique(void *t)
{
	s_client *c = (s_client *) t;

	for (int i = 0; i < 10; i++) {
		search_and_insert(db, topic0, id, NULL, c->pipe_id);
		cvector(void *) v = NULL;
		v                 = search_client(db, topic0);
		cvector_free(v);
		print_db_tree(db);
		search_and_delete(db, topic0, c->pipe_id);
	}
	pthread_exit(NULL);
}

static void
test_concurrent()
{
	pthread_t threads[NUM_THREADS];
	int       rc;
	long      t;
	void *    status;
	for (t = 0; t < NUM_THREADS; t++) {
		printf("In main: creating thread %ld\n", t);
		rc = pthread_create(
		    &threads[t], NULL, test_unique, (void *) &client[t % 10]);
		if (rc) {
			printf(
			    "ERROR; return code from pthread_create() is %d\n",
			    rc);
			exit(-1);
		}
	}

	for (t = 0; t < NUM_THREADS; t++) {
		rc = pthread_join(threads[t], &status);
		if (rc) {
			printf(
			    "ERROR; return code from pthread_join() is %d\n",
			    rc);
			exit(-1);
		}
		printf("Main: completed join with thread %ld having a status "
		       "of %ld\n",
		    t, (long) status);
	}

	printf("Main: program completed. Exiting.\n");

	/* Last thing that main() should do */
	// pthread_exit(NULL);
}

static void
test_insert_retain()
{
	search_insert_retain(db_ret, topic00, &retain0);
	print_db_tree(db_ret);
	search_insert_retain(db_ret, topic01, &retain1);
	print_db_tree(db_ret);
	search_insert_retain(db_ret, topic02, &retain2);
	print_db_tree(db_ret);
	search_insert_retain(db_ret, topic03, &retain3);
	print_db_tree(db_ret);
	search_insert_retain(db_ret, topic04, &retain4);
	print_db_tree(db_ret);
	search_insert_retain(db_ret, topic05, &retain5);
	print_db_tree(db_ret);
	search_insert_retain(db_ret, topic06, &retain6);
	print_db_tree(db_ret);
	search_insert_retain(db_ret, topic07, &retain7);
	print_db_tree(db_ret);
	search_insert_retain(db_ret, topic08, &retain8);
	print_db_tree(db_ret);
	search_insert_retain(db_ret, topic09, &retain9);
	print_db_tree(db_ret);
}

static void
test_delete_retain()
{
	search_delete_retain(db_ret, topic00);
	print_db_tree(db_ret);
	search_delete_retain(db_ret, topic01);
	print_db_tree(db_ret);
	search_delete_retain(db_ret, topic02);
	print_db_tree(db_ret);
	search_delete_retain(db_ret, topic03);
	print_db_tree(db_ret);
	search_delete_retain(db_ret, topic04);
	print_db_tree(db_ret);
	search_delete_retain(db_ret, topic05);
	print_db_tree(db_ret);
	search_delete_retain(db_ret, topic06);
	print_db_tree(db_ret);
	search_delete_retain(db_ret, topic07);
	print_db_tree(db_ret);
	search_delete_retain(db_ret, topic08);
	print_db_tree(db_ret);
	search_delete_retain(db_ret, topic09);
	print_db_tree(db_ret);
}

int
main(int argc, char *argv[])
{
	puts("\n----------------TEST START------------------");

	// create_db_tree(&db);

	// test_insert();
	// test_concurrent();

	// for (int i = 0; i < 100; i++) {
	//         cvector(void*) v =  NULL;
	//         v = search_client(db, topic0);
	//         cvector_free(v);
	// }
	// test_delete();
	// // test_search_client();
	//
	// print_db_tree(db);
	// destory_db_tree(db);

	create_db_tree(&db_ret);
	test_insert_retain();
	puts("=======================================");
	retain_msg **r = search_retain(db_ret, topic6);
	for (int i = 0; i < cvector_size(r); i++) {
		if (r[i]) {
			printf("%s\t", r[i]->m);
		}
	}
	puts("");
	puts("=======================================");
	test_delete_retain();

	destory_db_tree(db_ret);
	puts("---------------TEST FINISHED----------------\n");

	return 0;
}
