#include <string.h>
#include "include/nanolib.h" 

#define NUM_THREADS 8

db_tree *db = NULL;

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
// char topic0[] = "zhang/bei/hai";
// char topic1[] = "zhang/bei/aih";
// char topic2[] = "zhang/bei/iah";
// char topic3[] = "zhang/ee/aa";
// char topic4[] = "zhang/ee/bb";
// char topic5[] = "zhang/ee/cc";
// char topic6[] = "aa/xx/yy";
// char topic7[] = "bb/zz/aa";
// char topic8[] = "cc/dd/aa";
// char topic9[] = "www/xxx/zz";

////////////////////////////////////
s_client client0 = {"150429", NULL};
s_client client1 = {"150428", NULL};
s_client client2 = {"150427", NULL};
s_client client3 = {"150426", NULL};
s_client client4 = {"150425", NULL};
s_client client5 = {"150424", NULL};
s_client client6 = {"150423", NULL};
s_client client7 = {"150422", NULL};
s_client client8 = {"150421", NULL};
s_client client9 = {"150420", NULL};


s_client client[] = {
        {"150429", NULL},
        {"150428", NULL},
        {"150427", NULL},
        {"150426", NULL},
        {"150425", NULL},
        {"150424", NULL},
        {"150423", NULL},
        {"150422", NULL},
        {"150421", NULL},
        {"150420", NULL},
};


static void test_insert() 
{
        search_and_insert(db, topic0, client0.id, NULL);
        print_db_tree(db);
        search_and_insert(db, topic1, client1.id, NULL);
        print_db_tree(db);
        search_and_insert(db, topic2, client2.id, NULL);
        print_db_tree(db);
        search_and_insert(db, topic3, client3.id, NULL);
        print_db_tree(db);
        search_and_insert(db, topic4, client4.id, NULL);
        print_db_tree(db);
        search_and_insert(db, topic5, client5.id, NULL);
        print_db_tree(db);
        search_and_insert(db, topic6, client6.id, NULL);
        print_db_tree(db);
        search_and_insert(db, topic7, client7.id, NULL);
        print_db_tree(db);
        search_and_insert(db, topic8, client8.id, NULL);
        print_db_tree(db);
        search_and_insert(db, topic9, client9.id, NULL);
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

static void test_delete()
{
        puts("================begin delete===============");
        search_and_delete(db, topic0, &client0);
        print_db_tree(db);
        search_and_delete(db, topic1, &client1);
        print_db_tree(db);
        search_and_delete(db, topic2, &client2);
        print_db_tree(db);
        search_and_delete(db, topic3, &client3);
        print_db_tree(db);
        search_and_delete(db, topic4, &client4);
        print_db_tree(db);
        search_and_delete(db, topic5, &client5);
        print_db_tree(db);
        search_and_delete(db, topic6, &client6);
        print_db_tree(db);
        search_and_delete(db, topic7, &client7);
        print_db_tree(db);
        search_and_delete(db, topic8, &client8);
        print_db_tree(db);
        search_and_delete(db, topic9, &client9);
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

static void *test_unique(void *t)
{
        s_client *c = (s_client*)t;

        for (int i = 0; i < 10000; i++) {
                // search_and_insert(db, topic0, c);
                // search_and_insert(db, topic0, c);
                search_and_insert(db, topic0, c->id, NULL);
                // cvector(s_client*) v =  NULL;
                // v = search_client(db, topic0);
                // print_db_tree(db);
                search_and_delete(db, topic0, c);
        }
        pthread_exit(NULL);
}

static void test_concurrent()
{
        pthread_t threads[NUM_THREADS];
        int rc;
        long t;
        void *status;
        for(t=0; t<NUM_THREADS; t++){
                printf("In main: creating thread %ld\n", t);
                rc = pthread_create(&threads[t], NULL, test_unique, (void *)&client[t%10]);
                if (rc){
                        printf("ERROR; return code from pthread_create() is %d\n", rc);
                        exit(-1); }
        }


        for(t=0; t<NUM_THREADS; t++) {
                rc = pthread_join(threads[t], &status);
                if (rc) {
                        printf("ERROR; return code from pthread_join() is %d\n", rc);
                        exit(-1);
                }
                printf("Main: completed join with thread %ld having a status of %ld\n",t,(long)status);
        }

        printf("Main: program completed. Exiting.\n");

        /* Last thing that main() should do */
        // pthread_exit(NULL);
}

int main(int argc, char *argv[])
{
        puts("\n----------------TEST START------------------");

        create_db_tree(&db);


        test_concurrent();
        test_insert();
        test_delete();
        // test_search_client();
        
        // print_db_tree(db);

        puts("---------------TEST FINISHED----------------\n");
        destory_db_tree(db);

        return 0;
}
