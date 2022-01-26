#include "mqtt_db.h"
#ifndef TEST_H

#define TEST_NUM_THREADS 8
#define TEST_QUE_SIZE 13
#define TEST_MSG_SIZE 16
#define TEST_ARRAY_SIZE 10
#define TEST_LOOP 100

typedef void *test_single(void *args);
int dbtree_test();
int hash_test();
void *test_concurrent(test_single single);

#endif
