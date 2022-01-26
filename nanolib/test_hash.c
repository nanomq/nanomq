#include "include/hash_table.h"
#include "include/dbg.h"
#include "include/test.h"
#include <stdlib.h>
#include <string.h>


#define TABLE_SZ 8

typedef struct {
	int 	key;
	char 	*topic;
} test_table;

test_table table1[] = {
	{ .key = 1, .topic = "test1" },
	{ .key = 10, .topic = "test10" },
	{ .key = 100, .topic = "test100" },
	{ .key = 1000, .topic = "test1000" },
	{ .key = 10000, .topic = "test10000" },
	{ .key = 100000, .topic = "test100000" },
	{ .key = 1000000, .topic = "test1000000" },
	{ .key = 10000000, .topic = "test10000000" }
};

test_table table2[] = {
	{ .key = 1, .topic = "test10000000" },
	{ .key = 10, .topic = "test1000000" },
	{ .key = 100, .topic = "test100000" },
	{ .key = 1000, .topic = "test10000" },
	{ .key = 10000, .topic = "test1000" },
	{ .key = 100000, .topic = "test100" },
	{ .key = 1000000, .topic = "test10" },
	{ .key = 10000000, .topic = "test1" }

	// TODO This will cause same id same topic question.
	// { .key = 1, .topic = "test1" },
	// { .key = 10, .topic = "test10" },
	// { .key = 100, .topic = "test100" },
	// { .key = 1000, .topic = "test1000" },
	// { .key = 10000, .topic = "test10000" },
	// { .key = 100000, .topic = "test100000" },
	// { .key = 1000000, .topic = "test1000000" },
	// { .key = 10000000, .topic = "test10000000" }

};

static void assert_str(const char *s1, const char *s2)
{
	if (strcmp(s1, s2)) {
		log_err("Test failed lv: %s, rv: %s", s1, s2);
		exit(0);
	}

	return;
}

static void test_check_alias_table(void)
{

	dbhash_del_alias(table1[0].key);
	dbhash_add_alias(table1[0].key, table1[0].topic);
	const char *r = dbhash_find_alias(table1[0].key);
	check(r, "Test failed. Can not find topic of alias: %d", table1[0].key);
	assert_str(r, table1[0].topic);

	dbhash_del_alias(table1[0].key);
	r = dbhash_find_alias(table1[0].key);
	check(!r, "Test failed. Find topic of alias has been deleted: %d", table1[0].key);

	dbhash_add_alias(table1[1].key, table1[1].topic);
	dbhash_add_alias(table1[2].key, table1[2].topic);

	r = dbhash_find_alias(table1[1].key);
	check(r, "Test failed. Can not find topic of alias: %d", table1[1].key);
	assert_str(r, table1[1].topic);
	dbhash_del_alias(table1[1].key);
	r = dbhash_find_alias(table1[1].key);
	check(!r, "Test failed. Find topic of alias has been deleted: %d", table1[1].key);

	r = dbhash_find_alias(table1[2].key);
	check(r, "Test failed. Can not find topic of alias: %d", table1[2].key);
	assert_str(r, table1[2].topic);
	dbhash_del_alias(table1[2].key);
	r = dbhash_find_alias(table1[2].key);
	check(!r, "Test failed. Find topic of alias has been deleted: %d", table1[2].key);

error:
	return;
}

static void test_alias_table(void)
{

	for (size_t i = 0; i < TABLE_SZ; i++) {

	// size_t i = 0;
		dbhash_add_alias(table1[i].key, table1[i].topic);
		// dbhash_find_alias(table1[i].key);
		dbhash_del_alias(table1[i].key);

		dbhash_add_alias(table2[i].key, table2[i].topic);
		// dbhash_find_alias(table2[i].key);
		dbhash_del_alias(table2[i].key);

	}

	return;
}

static void test_check_pipe_table()
{
	dbhash_insert_topic(table1[0].key, table1[0].topic);
	dbhash_insert_topic(table1[1].key, table1[1].topic);
	dbhash_insert_topic(table1[2].key, table1[2].topic);

	dbhash_insert_topic(table2[0].key, table2[0].topic);
	dbhash_insert_topic(table2[1].key, table2[1].topic);
	dbhash_insert_topic(table2[2].key, table2[2].topic);

	check(dbhash_check_topic(table1[0].key, table1[0].topic), "table1[0] was not find.");
	check(dbhash_check_topic(table1[1].key, table1[1].topic), "table1[1] was not find.");
	check(dbhash_check_topic(table1[2].key, table1[2].topic), "table1[2] was not find.");

	check(dbhash_check_topic(table2[0].key, table2[0].topic), "table2[0] was not find.");
	check(dbhash_check_topic(table2[1].key, table2[1].topic), "table2[1] was not find.");
	check(dbhash_check_topic(table2[2].key, table2[2].topic), "table2[2] was not find.");

	topic_queue *tq1 = dbhash_get_topic_queue(table1[0].key);
	topic_queue *tq2 = dbhash_get_topic_queue(table1[1].key);
	topic_queue *tq3 = dbhash_get_topic_queue(table1[2].key);
	check(tq1, "Topic queue should not be null");
	check(tq2, "Topic queue should not be null");
	check(tq3, "Topic queue should not be null");
	assert_str(tq1->topic, table1[0].topic);
	assert_str(tq1->next->topic, table2[0].topic);
	assert_str(tq2->topic, table1[1].topic);
	assert_str(tq2->next->topic, table2[1].topic);
	assert_str(tq3->topic, table1[2].topic);
	assert_str(tq3->next->topic, table2[2].topic);

	dbhash_del_topic(table1[0].key, table1[0].topic);
	dbhash_del_topic(table1[0].key, table2[0].topic);
	check(false == dbhash_check_topic(table1[0].key, table1[0].topic), "Topic: table1[0] delete failed!");
	
	check(false == dbhash_check_topic(table1[0].key, table1[2].topic), "Topic: table2[0] delete failed!");

	check(dbhash_check_id(table1[1].key), "Id should be found!");
	dbhash_del_topic_queue(table1[1].key);
	check(false == dbhash_check_id(table1[1].key), "Id should not be found!");

	check(dbhash_check_topic(table1[2].key, table1[2].topic), "Topic: table1[2] should not be destoried!");
	check(dbhash_check_topic(table2[2].key, table2[2].topic), "Topic: table2[2] should not be destoried!");
	dbhash_del_topic(table1[2].key, table1[2].topic);
	dbhash_del_topic(table2[2].key, table2[2].topic);
	check(false == dbhash_check_topic(table1[2].key, table1[2].topic), "Topic: table1[2] delete failed!");
	check(false == dbhash_check_topic(table2[2].key, table2[2].topic), "Topic: table2[2] delete failed!");

error:
	return;
}

static void test_pipe_table()
{

	for (size_t i = 0; i < TABLE_SZ; i++) {
		dbhash_insert_topic(table1[i].key, table1[i].topic);
		dbhash_insert_topic(table2[i].key, table2[i].topic);

		dbhash_check_topic(table1[i].key, table1[i].topic);
		dbhash_check_topic(table2[i].key, table2[i].topic);

		topic_queue *tq = dbhash_get_topic_queue(table1[i].key);


		dbhash_del_topic(table1[i].key, table1[i].topic);
		dbhash_del_topic(table2[i].key, table2[i].topic);
		dbhash_check_id(table1[i].key);

		dbhash_check_topic(table1[i].key, table1[i].topic);
		dbhash_check_topic(table2[i].key, table2[i].topic);

		dbhash_insert_topic(table1[i].key, table1[i].topic);
		dbhash_insert_topic(table2[i].key, table2[i].topic);
		dbhash_del_topic_queue(table1[i].key);

	}

	return;
}


static void test_check_cached_table()
{
	dbhash_insert_topic(table1[0].key, table1[0].topic);
	dbhash_insert_topic(table1[0].key, table2[0].topic);

	dbhash_insert_topic(table1[1].key, table1[1].topic);
	dbhash_insert_topic(table1[1].key, table2[1].topic);

	dbhash_cache_topic_all(table1[0].key, table1[0].key);
	dbhash_cache_topic_all(table1[1].key, table1[1].key);

	topic_queue *tq1 = dbhash_get_cached_topic(table1[0].key);
	topic_queue *tq2 = dbhash_get_cached_topic(table1[1].key);

	check(tq1, "Topic queue should not be null");
	check(tq2, "Topic queue should not be null");
	assert_str(tq1->topic, table1[0].topic);
	assert_str(tq1->next->topic, table2[0].topic);
	assert_str(tq2->topic, table1[1].topic);
	assert_str(tq2->next->topic, table2[1].topic);

	tq1 = dbhash_get_topic_queue(table1[0].key);
	tq2 = dbhash_get_topic_queue(table1[1].key);
	check(!tq1, "Topic queue should be null");
	check(!tq2, "Topic queue should be null");

	dbhash_restore_topic_all(table1[0].key, table1[0].key);
	dbhash_restore_topic_all(table1[1].key, table1[1].key);
	tq1 = dbhash_get_cached_topic(table1[0].key);
	tq2 = dbhash_get_cached_topic(table1[1].key);

	check(!tq1, "Topic queue should be null");
	check(!tq2, "Topic queue should be null");

	tq1 = dbhash_get_topic_queue(table1[0].key);
	tq2 = dbhash_get_topic_queue(table1[1].key);
	check(tq1, "Topic queue should not be null");
	check(tq2, "Topic queue should not be null");
	assert_str(tq1->topic, table1[0].topic);
	assert_str(tq1->next->topic, table2[0].topic);
	assert_str(tq2->topic, table1[1].topic);
	assert_str(tq2->next->topic, table2[1].topic);

	dbhash_cache_topic_all(table1[0].key, table1[0].key);
	dbhash_cache_topic_all(table1[1].key, table1[1].key);

	check(dbhash_cached_check_id(table1[0].key), "Cached id do not found!");
	check(dbhash_cached_check_id(table1[1].key), "Cached id do not found!");

	dbhash_del_cached_topic_all(table1[0].key);
	dbhash_del_cached_topic_all(table1[1].key);

	tq1 = dbhash_get_cached_topic(table1[0].key);
	tq2 = dbhash_get_cached_topic(table1[1].key);

	check(!tq1, "Topic queue should be null");
	check(!tq2, "Topic queue should be null");

error:
	return;
}


static void test_cached_table()
{

	for (size_t i = 0; i < TABLE_SZ; i++) {
		dbhash_insert_topic(table1[i].key, table1[i].topic);
		dbhash_insert_topic(table2[i].key, table2[i].topic);

		dbhash_check_topic(table1[i].key, table1[i].topic);
		dbhash_check_topic(table2[i].key, table2[i].topic);

		dbhash_cache_topic_all(table1[i].key, table1[i].key);

		topic_queue *tq = dbhash_get_cached_topic(table1[i].key);

		tq = dbhash_get_topic_queue(table1[i].key);
		
		dbhash_restore_topic_all(table1[i].key, table1[i].key);

		tq = dbhash_get_cached_topic(table1[i].key);

		tq = dbhash_get_topic_queue(table1[i].key);

		dbhash_cache_topic_all(table1[i].key, table1[i].key);
		dbhash_cached_check_id(table1[i].key);
		dbhash_del_cached_topic_all(table1[i].key);
		tq = dbhash_get_cached_topic(table1[i].key);
	}

	return;
}

static void test_check(void)
{
	test_check_alias_table();
	test_check_pipe_table();
	test_check_cached_table();
}

static void *test_single_thread(void * args)
{
	for (size_t i = 0; i < TEST_LOOP; i++) {
		test_alias_table();
		test_pipe_table();
		test_cached_table();
	}

	return NULL;
}


int hash_test() 
{

	log_info("TEST STARTED");
	dbhash_init_alias_table();
	dbhash_init_pipe_table();
	dbhash_init_cached_table();
	test_check();
	test_concurrent(test_single_thread);

	for (size_t i = 0; i < TABLE_SZ; i++) {
		const char *r = dbhash_find_alias(table1[i].key);
		check(!r, "Should not found alias");
		r = dbhash_find_alias(table2[i].key);
		check(!r, "Should not found alias");
	}


	for (size_t j = 0; j < TABLE_SZ; j++) {
		topic_queue *tq = dbhash_get_topic_queue(table1[j].key);
		check(!tq, "Should be NULL");
		tq = dbhash_get_cached_topic(table1[j].key);
		check(!tq, "Should be NULL");

	}

	dbhash_destroy_alias_table();
	dbhash_destroy_pipe_table();
	dbhash_destroy_cached_table();

	log_info("TEST FINISHED");
error:
	return 0;
}
