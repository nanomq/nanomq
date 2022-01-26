#include "include/mqtt_db.h"
#include "include/nanolib.h"
#include "include/test.h"
#include <assert.h>
#include <string.h>


dbtree *db     = NULL;
dbtree *db_ret = NULL;

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

///////////for wildcard////////////
char share0[] = "$share/a/zhang/bei/hai";
char share1[] = "$share/a/zhang/bei/hai";
char share2[] = "$share/a/zhang/bei/hai";
char share3[] = "$share/a/zhang/bei/hai";
char share4[] = "$share/a/zhang/bei/hai";
char share5[] = "$share/a/zhang/bei/hai";
char share6[] = "$share/a/zhang/bei/hai";
char share7[] = "$share/a/+/+/+";
char share8[] = "$share/a/+/+/+";
char share9[] = "$share/a/zhang/bei/hai";

// char share0[] = "$share/a/zhang/bei/hai";
// char share1[] = "$share/a/zhang/#";
// char share2[] = "$share/a/#";
// char share3[] = "$share/a/zhang/bei/#";
// char share4[] = "$share/a/zhang/+/hai";
// char share5[] = "$share/b/zhang/bei/+";
// char share6[] = "$share/b/zhang/bei/h/ai";
// char share7[] = "$share/b/+/+/+";
// char share8[] = "$share/b/zhang/+/+";
// char share9[] = "$share/b/zhang/bei/hai";
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
dbtree_client client0 = {
	.session_id = 250429, .pipe_id = 150429, (void *) &"350429"
};
dbtree_client client1 = {
	.session_id = 250420, .pipe_id = 150420, (void *) &"350420"
};
dbtree_client client2 = {
	.session_id = 250427, .pipe_id = 150427, (void *) &"350427"
};
dbtree_client client3 = {
	.session_id = 250426, .pipe_id = 150426, (void *) &"350426"
};
dbtree_client client4 = {
	.session_id = 250425, .pipe_id = 150425, (void *) &"350425"
};
dbtree_client client5 = {
	.session_id = 250424, .pipe_id = 150424, (void *) &"350424"
};
dbtree_client client6 = {
	.session_id = 250423, .pipe_id = 150423, (void *) &"350423"
};
dbtree_client client7 = {
	.session_id = 250422, .pipe_id = 150422, (void *) &"350422"
};
dbtree_client client8 = {
	.session_id = 250421, .pipe_id = 150421, (void *) &"350421"
};
dbtree_client client9 = {
	.session_id = 250420, .pipe_id = 150420, (void *) &"350420"
};

dbtree_retain_msg retain0 = { 1, true, "150429", NULL };
dbtree_retain_msg retain1 = { 1, true, "150428", NULL };
dbtree_retain_msg retain2 = { 1, true, "150427", NULL };
dbtree_retain_msg retain3 = { 1, true, "150426", NULL };
dbtree_retain_msg retain4 = { 1, true, "150425", NULL };
dbtree_retain_msg retain5 = { 1, true, "150424", NULL };
dbtree_retain_msg retain6 = { 1, true, "150423", NULL };
dbtree_retain_msg retain7 = { 1, true, "150422", NULL };
dbtree_retain_msg retain8 = { 1, true, "150421", NULL };
dbtree_retain_msg retain9 = { 1, true, "150420", NULL };

dbtree_client client[] = {
	{ 230429, 130429, NULL },
	{ 230428, 130428, NULL },
	{ 230427, 130427, NULL },
	{ 230426, 130426, NULL },
	{ 230425, 130425, NULL },
	{ 230424, 130424, NULL },
	{ 230423, 130423, NULL },
	{ 230422, 130422, NULL },
	{ 230421, 130421, NULL },
	{ 230420, 130420, NULL },
};

static void
test_insert_client()
{
	dbtree_insert_client(db, topic0, client0.ctxt, client0.pipe_id);
	dbtree_print(db);
	dbtree_insert_client(db, topic1, client1.ctxt, client1.pipe_id);
	dbtree_print(db);
	dbtree_insert_client(db, topic2, client2.ctxt, client2.pipe_id);
	dbtree_print(db);
	dbtree_insert_client(db, topic3, client3.ctxt, client3.pipe_id);
	dbtree_print(db);
	dbtree_insert_client(db, topic4, client4.ctxt, client4.pipe_id);
	dbtree_print(db);
	dbtree_insert_client(db, topic5, client5.ctxt, client5.pipe_id);
	dbtree_print(db);
	dbtree_insert_client(db, topic6, client6.ctxt, client6.pipe_id);
	dbtree_print(db);
	dbtree_insert_client(db, topic7, client7.ctxt, client7.pipe_id);
	dbtree_print(db);
	dbtree_insert_client(db, topic8, client8.ctxt, client8.pipe_id);
	dbtree_print(db);
	dbtree_insert_client(db, topic9, client9.ctxt, client9.pipe_id);
	dbtree_print(db);
}


static void
test_insert_shared_client()
{
	dbtree_insert_client(db, share0, client0.ctxt, client0.pipe_id);
	dbtree_print(db);
	dbtree_insert_client(db, share1, client1.ctxt, client1.pipe_id);
	dbtree_print(db);
	dbtree_insert_client(db, share2, client2.ctxt, client2.pipe_id);
	dbtree_print(db);
	dbtree_insert_client(db, share3, client3.ctxt, client3.pipe_id);
	dbtree_print(db);
	dbtree_insert_client(db, share4, client4.ctxt, client4.pipe_id);
	dbtree_print(db);
	dbtree_insert_client(db, share5, client5.ctxt, client5.pipe_id);
	dbtree_print(db);
	dbtree_insert_client(db, share6, client6.ctxt, client6.pipe_id);
	dbtree_print(db);
	dbtree_insert_client(db, share7, client7.ctxt, client7.pipe_id);
	dbtree_print(db);
	dbtree_insert_client(db, share8, client8.ctxt, client8.pipe_id);
	dbtree_print(db);
	dbtree_insert_client(db, share9, client9.ctxt, client9.pipe_id);
	dbtree_print(db);
}

static void
test_delete_shared_client()
{
	puts("================begin delete client===============");
	dbtree_delete_client(db, share0, client0.session_id, client0.pipe_id);
	dbtree_print(db);
	dbtree_delete_client(db, share1, client1.session_id, client1.pipe_id);
	dbtree_print(db);
	dbtree_delete_client(db, share2, client2.session_id, client2.pipe_id);
	dbtree_print(db);
	dbtree_delete_client(db, share3, client3.session_id, client3.pipe_id);
	dbtree_print(db);
	dbtree_delete_client(db, share4, client4.session_id, client4.pipe_id);
	dbtree_print(db);
	dbtree_delete_client(db, share5, client5.session_id, client5.pipe_id);
	dbtree_print(db);
	dbtree_delete_client(db, share6, client6.session_id, client6.pipe_id);
	dbtree_print(db);
	dbtree_delete_client(db, share7, client7.session_id, client7.pipe_id);
	dbtree_print(db);
	dbtree_delete_client(db, share8, client8.session_id, client8.pipe_id);
	dbtree_print(db);
	dbtree_delete_client(db, share9, client9.session_id, client9.pipe_id);
	dbtree_print(db);
}


static void
test_delete_client()
{
	puts("================begin delete client===============");
	dbtree_delete_client(db, topic0, client0.session_id, client0.pipe_id);
	dbtree_print(db);
	dbtree_delete_client(db, topic1, client1.session_id, client1.pipe_id);
	dbtree_print(db);
	dbtree_delete_client(db, topic2, client2.session_id, client2.pipe_id);
	dbtree_print(db);
	dbtree_delete_client(db, topic3, client3.session_id, client3.pipe_id);
	dbtree_print(db);
	dbtree_delete_client(db, topic4, client4.session_id, client4.pipe_id);
	dbtree_print(db);
	dbtree_delete_client(db, topic5, client5.session_id, client5.pipe_id);
	dbtree_print(db);
	dbtree_delete_client(db, topic6, client6.session_id, client6.pipe_id);
	dbtree_print(db);
	dbtree_delete_client(db, topic7, client7.session_id, client7.pipe_id);
	dbtree_print(db);
	dbtree_delete_client(db, topic8, client8.session_id, client8.pipe_id);
	dbtree_print(db);
	dbtree_delete_client(db, topic9, client9.session_id, client9.pipe_id);
	dbtree_print(db);
}

static void
test_cache_session()
{
	puts("================begin cache session===============");
	dbtree_cache_session(db, topic0, client0.session_id, client0.pipe_id);
	dbtree_print(db);
	dbtree_cache_session(db, topic1, client1.session_id, client1.pipe_id);
	dbtree_print(db);
	dbtree_cache_session(db, topic2, client2.session_id, client2.pipe_id);
	dbtree_print(db);
	dbtree_cache_session(db, topic3, client3.session_id, client3.pipe_id);
	dbtree_print(db);
	dbtree_cache_session(db, topic4, client4.session_id, client4.pipe_id);
	dbtree_print(db);
	dbtree_cache_session(db, topic5, client5.session_id, client5.pipe_id);
	dbtree_print(db);
	dbtree_cache_session(db, topic6, client6.session_id, client6.pipe_id);
	dbtree_print(db);
	dbtree_cache_session(db, topic7, client7.session_id, client7.pipe_id);
	dbtree_print(db);
	dbtree_cache_session(db, topic8, client8.session_id, client8.pipe_id);
	dbtree_print(db);
	dbtree_cache_session(db, topic9, client9.session_id, client9.pipe_id);
	dbtree_print(db);
}

static void
test_delete_session()
{
	puts("================begin delete session===============");
	dbtree_delete_session(db, topic0, client0.session_id, client0.pipe_id);
	dbtree_print(db);
	dbtree_delete_session(db, topic1, client1.session_id, client1.pipe_id);
	dbtree_print(db);
	dbtree_delete_session(db, topic2, client2.session_id, client2.pipe_id);
	dbtree_print(db);
	dbtree_delete_session(db, topic3, client3.session_id, client3.pipe_id);
	dbtree_print(db);
	dbtree_delete_session(db, topic4, client4.session_id, client4.pipe_id);
	dbtree_print(db);
	dbtree_delete_session(db, topic5, client5.session_id, client5.pipe_id);
	dbtree_print(db);
	dbtree_delete_session(db, topic6, client6.session_id, client6.pipe_id);
	dbtree_print(db);
	dbtree_delete_session(db, topic7, client7.session_id, client7.pipe_id);
	dbtree_print(db);
	dbtree_delete_session(db, topic8, client8.session_id, client8.pipe_id);
	dbtree_print(db);
	dbtree_delete_session(db, topic9, client9.session_id, client9.pipe_id);
	dbtree_print(db);
}

static void
test_restore_client()
{
	puts("================begin delete session===============");
        void *ctxt_array[10];

        ctxt_array[0] = dbtree_restore_session(
	    db, topic0, client0.session_id, client0.pipe_id);
	dbtree_print(db);
        ctxt_array[1] = dbtree_restore_session(
	    db, topic1, client1.session_id, client1.pipe_id);
	dbtree_print(db);
	ctxt_array[2] = dbtree_restore_session(
	    db, topic2, client2.session_id, client2.pipe_id);
	dbtree_print(db);
	ctxt_array[3] = dbtree_restore_session(
	    db, topic3, client3.session_id, client3.pipe_id);
	dbtree_print(db);
	ctxt_array[4] = dbtree_restore_session(
	    db, topic4, client4.session_id, client4.pipe_id);
	dbtree_print(db);
	ctxt_array[5] = dbtree_restore_session(
	    db, topic5, client5.session_id, client5.pipe_id);
	dbtree_print(db);
	ctxt_array[6] = dbtree_restore_session(
	    db, topic6, client6.session_id, client6.pipe_id);
	dbtree_print(db);
	ctxt_array[7] = dbtree_restore_session(
	    db, topic7, client7.session_id, client7.pipe_id);
	dbtree_print(db);
	ctxt_array[8] = dbtree_restore_session(
	    db, topic8, client8.session_id, client8.pipe_id);
	dbtree_print(db);
	ctxt_array[9] = dbtree_restore_session(
	    db, topic9, client9.session_id, client9.pipe_id);
	dbtree_print(db);
        for (int i = 0; i < 10; i++) {
            log_info("%s", (char*)ctxt_array[i]);
        }
}

static void
test_search_client()
{
	puts("================test search client==============");
        size_t size = 0;
	char **v =
	    (char **) dbtree_find_clients_and_cache_msg(db, topic0, NULL, &size);

	if (v) {
		for (int i = 0; i < cvector_size(v); ++i) {
			log_info("ctxt: %s", v[i]);
		}
	}

	cvector_free(v);
}

static void
test_search_shared_client()
{
	puts("================test search shared client==============");
	for (int i = 0; i < 20; i++) {
        	size_t size = 0;
		// dbtree_print(db);
		char **v =
		    (char **) dbtree_find_shared_sub_clients(db, topic0, NULL, &size);
		// dbtree_print(db);

		if (v) {
			for (int i = 0; i < cvector_size(v); ++i) {
				log_info("ctxt: %s", v[i]);
			}
		}

		cvector_free(v);
	}
}

static void
test_search_session()
{
	puts("================test search session==============");
	char msg_que[TEST_QUE_SIZE][TEST_MSG_SIZE];
        size_t size = 0;
	for (int i = 0; i < TEST_QUE_SIZE; i++) {
		memset(msg_que[i], 0, TEST_MSG_SIZE);
		sprintf(msg_que[i], "message+%d", i);
		void **v = dbtree_find_clients_and_cache_msg(
		    db, topic0, (void *) msg_que[i], &size);
		cvector_free(v);
	}

	char **ret =
	    (char **) dbtree_restore_session_msg(db, client4.session_id);
	for (int i = 0; i < cvector_size(ret); i++) {
		printf("message: %s\n", ret[i]);
	}
	cvector_free(ret);
}

static void
test_cache_session_msg()
{
	puts("================test search session msg==============");
	char msg_que[TEST_ARRAY_SIZE][TEST_MSG_SIZE];
	for (int i = 0; i < TEST_ARRAY_SIZE; i++) {
		memset(msg_que[i], 0, TEST_MSG_SIZE);
		sprintf(msg_que[i], "message+%d", i);
		dbtree_cache_session_msg(
		    db, (void *) msg_que[i], client[i].session_id);

		char **ret = (char **) dbtree_restore_session_msg(
		    db, client[i].session_id);
		for (int i = 0; i < cvector_size(ret); i++) {
			printf("message: %s\n", ret[i]);
		}
		cvector_free(ret);
	}
}

static void
test_insert_retain()
{
	dbtree_insert_retain(db_ret, topic00, &retain0);
	dbtree_print(db_ret);
	dbtree_insert_retain(db_ret, topic01, &retain1);
	dbtree_print(db_ret);
	dbtree_insert_retain(db_ret, topic02, &retain2);
	dbtree_print(db_ret);
	dbtree_insert_retain(db_ret, topic03, &retain3);
	dbtree_print(db_ret);
	dbtree_insert_retain(db_ret, topic04, &retain4);
	dbtree_print(db_ret);
	dbtree_insert_retain(db_ret, topic05, &retain5);
	dbtree_print(db_ret);
	dbtree_insert_retain(db_ret, topic06, &retain6);
	dbtree_print(db_ret);
	dbtree_insert_retain(db_ret, topic07, &retain7);
	dbtree_print(db_ret);
	dbtree_insert_retain(db_ret, topic08, &retain8);
	dbtree_print(db_ret);
	dbtree_insert_retain(db_ret, topic09, &retain9);
	dbtree_print(db_ret);
}

static void
test_delete_retain()
{
	dbtree_delete_retain(db_ret, topic00);
	dbtree_print(db_ret);
	dbtree_delete_retain(db_ret, topic01);
	dbtree_print(db_ret);
	dbtree_delete_retain(db_ret, topic02);
	dbtree_print(db_ret);
	dbtree_delete_retain(db_ret, topic03);
	dbtree_print(db_ret);
	dbtree_delete_retain(db_ret, topic04);
	dbtree_print(db_ret);
	dbtree_delete_retain(db_ret, topic05);
	dbtree_print(db_ret);
	dbtree_delete_retain(db_ret, topic06);
	dbtree_print(db_ret);
	dbtree_delete_retain(db_ret, topic07);
	dbtree_print(db_ret);
	dbtree_delete_retain(db_ret, topic08);
	dbtree_print(db_ret);
	dbtree_delete_retain(db_ret, topic09);
	dbtree_print(db_ret);
}

static void *
test_single_thread(void *args)
{
	for (int i = 0; i < TEST_LOOP; i++) {
		log_info("TEST LOOP [%d]", i);

		test_insert_client();
		test_search_client();
		test_cache_session();
		test_restore_client();
		test_delete_client();

		test_insert_client();
		test_cache_session_msg();
		test_search_session();
		test_cache_session();
		test_search_session();
		test_delete_session();
	}
	return NULL;
}

void test_shared_sub()
{
	const char *null = NULL;
	const char *non_shared = "a/b/c";
	const char *shared = "$shared/a/b/c";
	assert(dbtree_check_shared_sub(null) == false);
	assert(dbtree_check_shared_sub(non_shared) == false);
	assert(dbtree_check_shared_sub(shared) == true);

	return;
}

int
dbtree_test()
{
	puts("\n----------------TEST START------------------");

	dbtree_create(&db);
	test_insert_shared_client();
	dbtree_print(db);
	test_search_shared_client();

	test_delete_shared_client();
	
	// test_single_thread(NULL);
	test_concurrent(test_single_thread);
	// dbtree_print(db);
	// dbtree_destory(db);
	//

	test_shared_sub();

	// dbtree_create(&db_ret);
	// test_insert_retain();
	// puts("=======================================");
	// dbtree_retain_msg **r = dbtree_find_retain(db_ret, topic6);
	// for (int i = 0; i < cvector_size(r); i++) {
	// 	if (r[i]) {
	// 		printf("%s\t", r[i]->m);
	// 	}
	// }
	// puts("");
	// puts("=======================================");
	// test_delete_retain();

	// dbtree_destory(db_ret);
	puts("---------------TEST FINISHED----------------\n");

	return 0;
}
