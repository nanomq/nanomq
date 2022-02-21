#include "include/test.h"
#include "stdio.h"
#include <getopt.h>


const char *help_info = "nano_test [--help <help>] [-a <all>] [-h <hash>] [-t <tree>]\n";
static struct option long_options[] = { 
	// { "clean", required_argument, NULL, 0 },
	{ "all", no_argument, NULL, 0 }, 
	{ "hash", no_argument, NULL, 0 }, 
	{ "tree", no_argument, NULL, 0 }, 
	{ "help", no_argument, NULL, 0 }, 
	{ NULL, 0, NULL, 0 } 
};

void*
test_concurrent(test_single single)
{
	pthread_t threads[TEST_NUM_THREADS];
	int       rc;
	long      t;
	void *    status;
	for (t = 0; t < TEST_NUM_THREADS; t++) {
		rc = pthread_create(
		    &threads[t], NULL, single, NULL);
		if (rc) {
			printf(
			    "ERROR; return code from pthread_create() is %d\n",
			    rc);
			exit(-1);
		}
	}

	for (t = 0; t < TEST_NUM_THREADS; t++) {
		rc = pthread_join(threads[t], &status);
		if (rc) {
			printf(
			    "ERROR; return code from pthread_join() is %d\n",
			    rc);
			exit(-1);
		}
	}

	return NULL;

	/* Last thing that main() should do */
	// pthread_exit(NULL);
}

int
test_opt(int argc, char **argv)
{

	if (argc < 2) {
		fprintf(stderr, "Usage: %s\n", help_info);
		exit(EXIT_FAILURE);
	}

	int c;
	// int digit_optind = 0;
	int option_index = 0;

	while ((c = getopt_long(argc, argv, "aht0",
	            long_options, &option_index)) != -1) {
		// int this_option_optind = optind ? optind : 1;
		switch (c) {
		case 0:
			if (!strcmp(long_options[option_index].name, "help")) {
				fprintf(stderr, "Usage: %s\n", help_info);
				exit(EXIT_FAILURE);
			} else if (!strcmp(long_options[option_index].name, "hash")) {
				hash_test();
			} else if (!strcmp(long_options[option_index].name, "tree")) {
				dbtree_test();
			} else if (!strcmp(long_options[option_index].name, "all")) {
				dbtree_test();
				hash_test();
			}
			break;
		case 'a':
			hash_test();
			dbtree_test();
			break;
		case 'h':
			hash_test();
			break;
		case 't':
			dbtree_test();
			break;
		case '?':
			fprintf(stderr, "Usage: %s\n", help_info);
			exit(EXIT_FAILURE);
			break;
		default:
			fprintf(stderr, "Usage: %s\n", help_info);
			exit(EXIT_FAILURE);
			printf(
			    "?? getopt returned character code 0%o ??\n", c);
		}
	}
	if (optind < argc) {
		fprintf(stderr, "Usage: %s\n", help_info);
		exit(EXIT_FAILURE);
		while (optind < argc)
			printf("%s ", argv[optind++]);
		printf("\n");
	}

	return 0;
}


int main(int argc, char *argv[])
{

	test_opt(argc, argv);
	return 0;
}
