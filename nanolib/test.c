#include <string.h>
#include "include/nanolib.h" 

db_tree *db = NULL;

int main(int argc, char *argv[])
{
	puts("\n----------------TEST START------------------");

 	create_db_tree(&db);

        ///////////for wildcard////////////
	char topic0[] = "zhang/bei/hai"; char topic1[] = "zhang/#";
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

        ///////////////////////////////////////
	search_and_insert(db, topic0, &client0);
        print_db_tree(db);
	search_and_insert(db, topic1, &client1);
        print_db_tree(db);
	search_and_insert(db, topic2, &client2);
        print_db_tree(db);
	search_and_insert(db, topic3, &client3);
        print_db_tree(db);
	search_and_insert(db, topic4, &client4);
        print_db_tree(db);
	search_and_insert(db, topic5, &client5);
        print_db_tree(db);
	search_and_insert(db, topic6, &client6);
        print_db_tree(db);
	search_and_insert(db, topic7, &client7);
        print_db_tree(db);
	search_and_insert(db, topic8, &client8);
        print_db_tree(db);
	search_and_insert(db, topic9, &client9);
        print_db_tree(db);
        // //////////////////////////////////////

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


        ////////////////////////////////////
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
        //////////////////////////////////////

        cvector(s_client*) v =  NULL;
        v = search_client(db, topic0);

        puts("================Return client==============");
	if (v) {
		for (int i = 0; i < cvector_size(v); ++i) {
                        log("client id: %s", v[i]->id);
                }
	}

	// if (v) {
	// 	for (int i = 0; i < cvector_size(v); ++i) {
        //                 for (int j = 0; j < cvector_size(v[i]); j++) {
        //                         log("client id: %s", v[i][j]->id);
        //                 }
        //         }

	// }

 	puts("---------------TEST FINISHED----------------\n");
        destory_db_tree(db);

 	return 0;
}

