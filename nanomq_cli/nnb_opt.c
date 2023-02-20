#if !defined(NANO_PLATFORM_WINDOWS) && defined(SUPP_BENCH)
//TODO support windows later
#include "nnb_opt.h"
#include "nnb_help.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <errno.h>
#include "nng/supplemental/nanolib/utils.h"

static int conn_opt_set(int argc, char **argv, nnb_conn_opt *opt);
static int sub_opt_set(int argc, char **argv, nnb_sub_opt *opt);
static int pub_opt_set(int argc, char **argv, nnb_pub_opt *opt);

static void
init_tls(tls_opt *tls)
{
	tls->enable  = NULL;
	tls->cacert  = NULL;
	tls->cert    = NULL;
	tls->key     = NULL;
	tls->keypass = NULL;
}

static void
destory_tls(tls_opt *tls)
{
	if (tls) {
		tls->enable = false;
		if (tls->cacert) {
			free(tls->cacert);
			tls->cacert = NULL;
		}
		if (tls->cert) {
			free(tls->cert);
			tls->cert = NULL;
		}
		if (tls->key) {
			free(tls->key);
			tls->key = NULL;
		}
		if (tls->keypass) {
			free(tls->keypass);
			tls->keypass = NULL;
		}
	}
}

nnb_conn_opt *
nnb_conn_opt_init(int argc, char **argv)
{
	nnb_conn_opt *opt = nng_alloc(sizeof(nnb_conn_opt));
	if (opt == NULL) {
		fprintf(stderr, "Memory alloc failed\n");
		exit(EXIT_FAILURE);
	}

	opt->port        = 1883;
	opt->version     = 4;
	opt->count       = 200;
	opt->startnumber = 0;
	opt->interval    = 10;
	opt->keepalive   = 300;
	opt->clean       = true;
	opt->username    = NULL;
	opt->password    = NULL;
	opt->host        = NULL;

	init_tls(&opt->tls);
	conn_opt_set(argc - 2, argv + 2, opt);
	if (opt->host == NULL) {
		opt->host = nng_strdup("localhost");
	}
	if (opt->version == 3) {
		opt->version = 4;
	}

	return opt;
}

void
nnb_conn_opt_destory(nnb_conn_opt *opt)
{
	if (opt) {
		if (opt->host) {
			nng_free(opt->host, strlen(opt->host));
			opt->host = NULL;
		}

		if (opt->username) {
			nng_free(opt->username, strlen(opt->username));
			opt->username = NULL;
		}

		if (opt->password) {
			nng_free(opt->password, strlen(opt->password));
			opt->password = NULL;
		}

		destory_tls(&opt->tls);

		nng_free(opt, sizeof(nnb_conn_opt));
		opt = NULL;
	}
}

nnb_pub_opt *
nnb_pub_opt_init(int argc, char **argv)
{
	nnb_pub_opt *opt = nng_alloc(sizeof(nnb_pub_opt));
	if (opt == NULL) {
		fprintf(stderr, "Memory alloc failed\n");
		exit(EXIT_FAILURE);
	}

	opt->port            = 1883;
	opt->version         = 4;
	opt->count           = 200;
	opt->size            = 256;
	opt->limit           = 0;
	opt->startnumber     = 0;
	opt->interval        = 10;
	opt->keepalive       = 300;
	opt->interval_of_msg = 1000;
	opt->retain          = false;
	opt->clean           = true;
	opt->username        = NULL;
	opt->password        = NULL;
	opt->host            = NULL;
	opt->topic           = NULL;
	opt->tls.enable      = NULL;
	opt->tls.cacert      = NULL;
	opt->tls.cert        = NULL;
	opt->tls.key         = NULL;
	opt->tls.keypass     = NULL;

	init_tls(&opt->tls);

	pub_opt_set(argc - 2, argv + 2, opt);
	if (opt->host == NULL) {
		opt->host = nng_strdup("localhost");
	}
	if (opt->version == 3) {
		opt->version = 4;
	}

	return opt;
}

void
nnb_pub_opt_destory(nnb_pub_opt *opt)
{
	if (opt) {
		if (opt->host) {
			nng_free(opt->host, strlen(opt->host));
			opt->host = NULL;
		}

		if (opt->username) {
			nng_free(opt->username, strlen(opt->username));
			opt->username = NULL;
		}

		if (opt->password) {
			nng_free(opt->password, strlen(opt->password));
			opt->password = NULL;
		}

		if (opt->topic) {
			nng_free(opt->topic, strlen(opt->topic));
			opt->topic = NULL;
		}

		destory_tls(&opt->tls);
		nng_free(opt, sizeof(nnb_pub_opt));
		opt = NULL;
	}
}

nnb_sub_opt *
nnb_sub_opt_init(int argc, char **argv)
{
	nnb_sub_opt *opt = nng_alloc(sizeof(nnb_sub_opt));
	if (opt == NULL) {
		fprintf(stderr, "Memory alloc failed\n");
		exit(EXIT_FAILURE);
	}

	opt->port        = 1883;
	opt->version     = 4;
	opt->count       = 200;
	opt->startnumber = 0;
	opt->interval    = 10;
	opt->keepalive   = 300;
	opt->qos         = 0;
	opt->clean       = true;
	opt->username    = NULL;
	opt->password    = NULL;
	opt->host        = NULL;
	opt->topic       = NULL;

	init_tls(&opt->tls);

	sub_opt_set(argc - 2, argv + 2, opt);
	if (opt->topic == NULL) {
		fprintf(stderr, "Error: topic required!\n");
		fprintf(stderr, "Usage: %s\n", sub_info);
		exit(EXIT_FAILURE);
	}
	if (opt->host == NULL) {
		opt->host = nng_strdup("localhost");
	}
	if (opt->version == 3) {
		opt->version = 4;
	}

	return opt;
}

void
nnb_sub_opt_destory(nnb_sub_opt *opt)
{
	if (opt) {
		if (opt->host) {
			nng_free(opt->host, strlen(opt->host));
			opt->host = NULL;
		}

		if (opt->username) {
			nng_free(opt->username, strlen(opt->username));
			opt->username = NULL;
		}

		if (opt->password) {
			nng_free(opt->password, strlen(opt->password));
			opt->password = NULL;
		}

		destory_tls(&opt->tls);
		nng_free(opt, sizeof(nnb_sub_opt));
		opt = NULL;
	}
}

// This reads a file into memory.  Care is taken to ensure that
// the buffer is one byte larger and contains a terminating
// NUL. (Useful for key files and such.)
static void
loadfile(const char *path, void **datap, size_t *lenp)
{
	FILE * f;
	size_t total_read      = 0;
	size_t allocation_size = BUFSIZ;
	char * fdata;
	char * realloc_result;

	if (strcmp(path, "-") == 0) {
		f = stdin;
	} else {
		if ((f = fopen(path, "rb")) == NULL) {
			fatal(
			    "Cannot open file %s: %s", path, strerror(errno));
		}
	}

	if ((fdata = malloc(allocation_size + 1)) == NULL) {
		fatal("Out of memory.");
	}

	while (1) {
		total_read += fread(
		    fdata + total_read, 1, allocation_size - total_read, f);
		if (ferror(f)) {
			if (errno == EINTR) {
				continue;
			}
			fatal(
			    "Read from %s failed: %s", path, strerror(errno));
		}
		if (feof(f)) {
			break;
		}
		if (total_read == allocation_size) {
			if (allocation_size > SIZE_MAX / 2) {
				fatal("Out of memory.");
			}
			allocation_size *= 2;
			if ((realloc_result = realloc(
			         fdata, allocation_size + 1)) == NULL) {
				free(fdata);
				fatal("Out of memory.");
			}
			fdata = realloc_result;
		}
	}
	if (f != stdin) {
		fclose(f);
	}
	fdata[total_read] = '\0';
	*datap            = fdata;
	*lenp             = total_read;
}

int
conn_opt_set(int argc, char **argv, nnb_conn_opt *opt)
{

	if (argc < 2) {
		fprintf(stderr, "Usage: %s\n", conn_info);
		exit(EXIT_FAILURE);
	}

	int    c;
	int    digit_optind = 0;
	int    option_index = 0;
	size_t sz           = 0;

	while ((c = getopt_long(argc, argv, "h:p:V:c:n:i:u:P:k:C:S0",
	            long_options, &option_index)) != -1) {
		int this_option_optind = optind ? optind : 1;
		switch (c) {
		case 0:
			// printf ("option %s",
			// long_options[option_index].name); if (optarg)
			// printf
			// (" with value %s", optarg); printf ("\n");
			if (!strcmp(long_options[option_index].name, "help")) {
				fprintf(stderr, "Usage: %s\n", conn_info);
				exit(EXIT_FAILURE);
			} else if (!strcmp(long_options[option_index].name,
			               "host")) {
				opt->host = nng_strdup(optarg);
			} else if (!strcmp(long_options[option_index].name,
			               "port")) {
				opt->port = atoi(optarg);
			} else if (!strcmp(long_options[option_index].name,
			               "version")) {
				opt->version = atoi(optarg);
			} else if (!strcmp(long_options[option_index].name,
			               "count")) {
				opt->count = atoi(optarg);
			} else if (!strcmp(long_options[option_index].name,
			               "startnumber")) {
				opt->startnumber = atoi(optarg);
			} else if (!strcmp(long_options[option_index].name,
			               "interval")) {
				opt->interval = atoi(optarg);
			} else if (!strcmp(long_options[option_index].name,
			               "username")) {
				opt->username = nng_strdup(optarg);
			} else if (!strcmp(long_options[option_index].name,
			               "password")) {
				opt->password = nng_strdup(optarg);
			} else if (!strcmp(long_options[option_index].name,
			               "keepalive")) {
				opt->keepalive = atoi(optarg);
			} else if (!strcmp(long_options[option_index].name,
			               "ssl")) {
				opt->tls.enable = true;
			} else if (!strcmp(long_options[option_index].name,
			               "cafile")) {
				if (opt->tls.cacert) {
					free(opt->tls.cacert);
					opt->tls.cacert = NULL;
				}
				loadfile(
				    optarg, (void **) &opt->tls.cacert, &sz);
			} else if (!strcmp(long_options[option_index].name,
			               "certfile")) {
				if (opt->tls.cert) {
					free(opt->tls.cert);
					opt->tls.cert = NULL;
				}
				loadfile(
				    optarg, (void **) &opt->tls.cert, &sz);
			} else if (!strcmp(long_options[option_index].name,
			               "keyfile")) {
				if (opt->tls.key) {
					free(opt->tls.key);
					opt->tls.key = NULL;
				}
				loadfile(optarg, (void **) &opt->tls.key, &sz);
			} else if (!strcmp(long_options[option_index].name,
			               "keypass")) {
				if (opt->tls.keypass) {
					nng_strfree(opt->tls.keypass);
					opt->tls.keypass = NULL;
				}
				opt->tls.keypass = nng_strdup(optarg);
			} else if (!strcmp(long_options[option_index].name,
			               "clean")) {
				if (!strcmp(optarg, "true")) {
					opt->clean = true;
				} else if (!strcmp(optarg, "false")) {
					opt->clean = false;
				} else {
					fprintf(
					    stderr, "Usage: %s\n", conn_info);
					exit(EXIT_FAILURE);
				}
			}

			break;
		case 'h':
			opt->host = nng_strdup(optarg);
			break;
		case 'p':
			opt->port = atoi(optarg);
			break;
		case 'V':
			opt->version = atoi(optarg);
			break;
		case 'c':
			opt->count = atoi(optarg);
			break;
		case 'n':
			opt->startnumber = atoi(optarg);
			break;
		case 'i':
			opt->interval = atoi(optarg);
			break;
		case 'u':
			opt->username = nng_strdup(optarg);
			break;
		case 'P':
			opt->password = nng_strdup(optarg);
			break;
		case 'k':
			opt->keepalive = atoi(optarg);
			break;
		case 'C':
			if (!strcmp(optarg, "true")) {
				opt->clean = true;
			} else if (!strcmp(optarg, "false")) {
				opt->clean = false;
			} else {
				fprintf(stderr, "Usage: %s\n", conn_info);
				exit(EXIT_FAILURE);
			}
			break;
		case 'S':
			opt->tls.enable = true;
			break;
		case '?':
			fprintf(stderr, "Usage: %s\n", conn_info);
			exit(EXIT_FAILURE);
			break;
		default:
			fprintf(stderr, "Usage: %s\n", conn_info);
			exit(EXIT_FAILURE);
			printf(
			    "?? getopt returned character code 0%o ??\n", c);
		}
	}

	// if (optind < argc) {
	// 	fprintf(stderr, "Usage: %s\n", conn_info);
	// 	exit(EXIT_FAILURE);
	// 	while (optind < argc)
	// 		printf("%s ", argv[optind++]);
	// 	printf("\n");
	// }

	return 0;
}

int
pub_opt_set(int argc, char **argv, nnb_pub_opt *opt)
{
	if (argc < 2) {
		fprintf(stderr, "Usage: %s\n", pub_info);
		exit(EXIT_FAILURE);
	}

	int c;
	int digit_optind = 0;
	int option_index = 0;
	size_t sz;

	while ((c = getopt_long(argc, argv,
	            "q:l:r:s:t:I:h:p:V:c:n:i:u:P:k:C:L:S0", long_options,
	            &option_index)) != -1) {
		int this_option_optind = optind ? optind : 1;
		switch (c) {
		case 0:
			// printf ("option %s",
			// long_options[option_index].name); if (optarg)
			// printf
			// (" with value %s", optarg); printf ("\n");
			if (!strcmp(long_options[option_index].name, "help")) {
				fprintf(stderr, "Usage: %s\n", pub_info);
				exit(EXIT_FAILURE);
			} else if (!strcmp(long_options[option_index].name,
			               "topic")) {
				opt->topic = nng_strdup(optarg);
			} else if (!strcmp(long_options[option_index].name,
			               "host")) {
				opt->host = nng_strdup(optarg);
			} else if (!strcmp(long_options[option_index].name,
			               "port")) {
				opt->port = atoi(optarg);
			} else if (!strcmp(long_options[option_index].name,
			               "version")) {
				opt->version = atoi(optarg);
			} else if (!strcmp(long_options[option_index].name,
			               "count")) {
				opt->count = atoi(optarg);
			} else if (!strcmp(long_options[option_index].name,
			               "startnumber")) {
				opt->startnumber = atoi(optarg);
			} else if (!strcmp(long_options[option_index].name,
			               "interval")) {
				opt->interval = atoi(optarg);
			} else if (!strcmp(long_options[option_index].name,
			               "username")) {
				opt->username = nng_strdup(optarg);
			} else if (!strcmp(long_options[option_index].name,
			               "password")) {
				opt->password = nng_strdup(optarg);
			} else if (!strcmp(long_options[option_index].name,
			               "keepalive")) {
				opt->keepalive = atoi(optarg);
			} else if (!strcmp(long_options[option_index].name,
			               "clean")) {
				if (!strcmp(optarg, "true")) {
					opt->clean = true;
				} else if (!strcmp(optarg, "false")) {
					opt->clean = false;
				} else {
					fprintf(
					    stderr, "Usage: %s\n", pub_info);
					exit(EXIT_FAILURE);
				}
			} else if (!strcmp(long_options[option_index].name,
			               "qos")) {
				opt->qos = atoi(optarg);
				if (opt->qos < 0 || opt->qos > 2) {
					fprintf(
					    stderr, "Error: qos invalided!\n");
					fprintf(
					    stderr, "Usage: %s\n", pub_info);
					exit(EXIT_FAILURE);
				}
			} else if (!strcmp(long_options[option_index].name,
			               "limit")) {
				opt->limit = atoi(optarg);
			} else if (!strcmp(long_options[option_index].name,
			               "retain")) {
				if (!strcmp(optarg, "true")) {
					opt->retain = true;
				} else if (!strcmp(optarg, "true")) {
					opt->retain = false;
				} else {
					fprintf(
					    stderr, "Usage: %s\n", pub_info);
					exit(EXIT_FAILURE);
				}
			} else if (!strcmp(long_options[option_index].name,
			               "size")) {
				opt->size = atoi(optarg);
			} else if (!strcmp(long_options[option_index].name,
			               "interval_of_msg")) {
				opt->interval_of_msg = atoi(optarg);
			} else if (!strcmp(long_options[option_index].name,
			               "ssl")) {
				opt->tls.enable = true;
			} else if (!strcmp(long_options[option_index].name,
			               "cafile")) {
				if (opt->tls.cacert) {
					free(opt->tls.cacert);
					opt->tls.cacert = NULL;
				}
				loadfile(
				    optarg, (void **) &opt->tls.cacert, &sz);
			} else if (!strcmp(long_options[option_index].name,
			               "certfile")) {
				if (opt->tls.cert) {
					free(opt->tls.cert);
					opt->tls.cert = NULL;
				}
				loadfile(
				    optarg, (void **) &opt->tls.cert, &sz);
			} else if (!strcmp(long_options[option_index].name,
			               "keyfile")) {
				if (opt->tls.key) {
					free(opt->tls.key);
					opt->tls.key = NULL;
				}
				loadfile(optarg, (void **) &opt->tls.key, &sz);
			} else if (!strcmp(long_options[option_index].name,
			               "keypass")) {
				if (opt->tls.keypass) {
					nng_strfree(opt->tls.keypass);
					opt->tls.keypass = NULL;
				}
				opt->tls.keypass = nng_strdup(optarg);
			}

			break;
		case 'l':
			opt->limit = atoi(optarg);
			break;
		case 't':
			opt->topic = nng_strdup(optarg);
			break;
		case 'q':
			opt->qos = atoi(optarg);
			if (opt->qos < 0 || opt->qos > 2) {
				fprintf(stderr, "Error: qos invalided!\n");
				fprintf(stderr, "Usage: %s\n", pub_info);
				exit(EXIT_FAILURE);
			}
			break;
		case 's':
			opt->size = atoi(optarg);
			break;
		case 'I':
			opt->interval_of_msg = atoi(optarg);
			break;
		case 'h':
			opt->host = nng_strdup(optarg);
			break;
		case 'p':
			opt->port = atoi(optarg);
			break;
		case 'V':
			opt->version = atoi(optarg);
			break;
		case 'c':
			opt->count = atoi(optarg);
			break;
		case 'n':
			opt->startnumber = atoi(optarg);
			break;
		case 'i':
			opt->interval = atoi(optarg);
			break;
		case 'u':
			opt->username = nng_strdup(optarg);
			break;
		case 'P':
			opt->password = nng_strdup(optarg);
			break;
		case 'k':
			opt->keepalive = atoi(optarg);
			break;
		case 'r':
			if (!strcmp(optarg, "true")) {
				opt->retain = true;
			} else if (!strcmp(optarg, "true")) {
				opt->retain = false;
			} else {
				fprintf(stderr, "Usage: %s\n", pub_info);
				exit(EXIT_FAILURE);
			}
			break;
		case 'C':
			if (!strcmp(optarg, "true")) {
				opt->clean = true;
			} else if (!strcmp(optarg, "false")) {
				opt->clean = false;
			} else {
				fprintf(stderr, "Usage: %s\n", pub_info);
				exit(EXIT_FAILURE);
			}
			break;
		case 'L':
			opt->limit = atoi(optarg);
			if (opt->limit < 0) {
				fprintf(stderr, "Usage: %s\n", pub_info);
				exit(EXIT_FAILURE);
			}
			break;
		case 'S':
			opt->tls.enable = true;
			break;
		case '?':
			fprintf(stderr, "Usage: %s\n", pub_info);
			exit(EXIT_FAILURE);
			break;
		default:
			fprintf(stderr, "Usage: %s\n", pub_info);
			exit(EXIT_FAILURE);
			printf(
			    "?? getopt returned character code 0%o ??\n", c);
		}
	}
	if (optind < argc) {
		fprintf(stderr, "Usage: %s\n", pub_info);
		exit(EXIT_FAILURE);
		while (optind < argc)
			printf("%s ", argv[optind++]);
		printf("\n");
	}

	if (opt->topic == NULL) {
		fprintf(stderr, "Error: topic required\n");
		fprintf(stderr, "Usage: %s\n", pub_info);
		exit(EXIT_FAILURE);
	}

	return 0;
}

int
sub_opt_set(int argc, char **argv, nnb_sub_opt *opt)
{

	if (argc < 2) {
		fprintf(stderr, "Usage: %s\n", sub_info);
		exit(EXIT_FAILURE);
	}

	int    c;
	int    digit_optind = 0;
	int    option_index = 0;
	size_t sz           = 0;

	while ((c = getopt_long(argc, argv, "q:t:h:p:V:c:n:i:u:P:k:C:S0",
	            long_options, &option_index)) != -1) {
		int this_option_optind = optind ? optind : 1;
		switch (c) {
		case 0:
			// printf ("option %s",
			// long_options[option_index].name); if (optarg)
			// printf
			// (" with value %s", optarg); printf ("\n");
			if (!strcmp(long_options[option_index].name, "help")) {
				fprintf(stderr, "Usage: %s\n", sub_info);
				exit(EXIT_FAILURE);
			} else if (!strcmp(long_options[option_index].name,
			               "topic")) {
				opt->topic = nng_strdup(optarg);
			} else if (!strcmp(long_options[option_index].name,
			               "host")) {
				opt->host = nng_strdup(optarg);
			} else if (!strcmp(long_options[option_index].name,
			               "port")) {
				opt->port = atoi(optarg);
			} else if (!strcmp(long_options[option_index].name,
			               "version")) {
				opt->version = atoi(optarg);
			} else if (!strcmp(long_options[option_index].name,
			               "count")) {
				opt->count = atoi(optarg);
			} else if (!strcmp(long_options[option_index].name,
			               "startnumber")) {
				opt->startnumber = atoi(optarg);
			} else if (!strcmp(long_options[option_index].name,
			               "interval")) {
				opt->interval = atoi(optarg);
			} else if (!strcmp(long_options[option_index].name,
			               "username")) {
				opt->username = nng_strdup(optarg);
			} else if (!strcmp(long_options[option_index].name,
			               "password")) {
				opt->password = nng_strdup(optarg);
			} else if (!strcmp(long_options[option_index].name,
			               "keepalive")) {
				opt->keepalive = atoi(optarg);
			} else if (!strcmp(long_options[option_index].name,
			               "clean")) {
				if (!strcmp(optarg, "true")) {
					opt->clean = true;
				} else if (!strcmp(optarg, "false")) {
					opt->clean = false;
				} else {
					fprintf(
					    stderr, "Usage: %s\n", sub_info);
					exit(EXIT_FAILURE);
				}
			} else if (!strcmp(long_options[option_index].name,
			               "qos")) {
				opt->qos = atoi(optarg);
				if (opt->qos < 0 || opt->qos > 2) {
					fprintf(
					    stderr, "Error: qos invalided!\n");
					fprintf(
					    stderr, "Usage: %s\n", sub_info);
					exit(EXIT_FAILURE);
				}
			} else if (!strcmp(long_options[option_index].name,
			               "ssl")) {
				opt->tls.enable = true;
			} else if (!strcmp(long_options[option_index].name,
			               "cafile")) {
				if (opt->tls.cacert) {
					free(opt->tls.cacert);
					opt->tls.cacert = NULL;
				}
				loadfile(
				    optarg, (void **) &opt->tls.cacert, &sz);
			} else if (!strcmp(long_options[option_index].name,
			               "certfile")) {
				if (opt->tls.cert) {
					free(opt->tls.cert);
					opt->tls.cert = NULL;
				}
				loadfile(
				    optarg, (void **) &opt->tls.cert, &sz);
			} else if (!strcmp(long_options[option_index].name,
			               "keyfile")) {
				if (opt->tls.key) {
					free(opt->tls.key);
					opt->tls.key = NULL;
				}
				loadfile(optarg, (void **) &opt->tls.key, &sz);
			} else if (!strcmp(long_options[option_index].name,
			               "keypass")) {
				if (opt->tls.keypass) {
					nng_strfree(opt->tls.keypass);
					opt->tls.keypass = NULL;
				}
				opt->tls.keypass = nng_strdup(optarg);
			}
			break;

		case 't':
			opt->topic = nng_strdup(optarg);
			break;
		case 'q':
			opt->qos = atoi(optarg);
			if (opt->qos < 0 || opt->qos > 2) {
				fprintf(stderr, "Error: qos invalided!\n");
				fprintf(stderr, "Usage: %s\n", sub_info);
				exit(EXIT_FAILURE);
			}

			break;
		case 'h':
			opt->host = nng_strdup(optarg);
			break;
		case 'p':
			opt->port = atoi(optarg);
			break;
		case 'V':
			opt->version = atoi(optarg);
			break;
		case 'c':
			opt->count = atoi(optarg);
			break;
		case 'n':
			opt->startnumber = atoi(optarg);
			break;
		case 'i':
			opt->interval = atoi(optarg);
			break;
		case 'u':
			opt->username = nng_strdup(optarg);
			break;
		case 'P':
			opt->password = nng_strdup(optarg);
			break;
		case 'k':
			opt->keepalive = atoi(optarg);
			break;
		case 'C':
			if (!strcmp(optarg, "true")) {
				opt->clean = true;
			} else if (!strcmp(optarg, "false")) {
				opt->clean = false;
			} else {
				fprintf(stderr, "Usage: %s\n", sub_info);
				exit(EXIT_FAILURE);
			}
			break;
		case 'S':
			opt->tls.enable = true;
			break;
		case '?':
			fprintf(stderr, "Usage: %s\n", sub_info);
			exit(EXIT_FAILURE);
			break;
		default:
			fprintf(stderr, "Usage: %s\n", sub_info);
			exit(EXIT_FAILURE);
			printf(
			    "?? getopt returned character code 0%o ??\n", c);
		}
	}
	if (optind < argc) {
		fprintf(stderr, "Usage: %s\n", sub_info);
		exit(EXIT_FAILURE);
		while (optind < argc)
			printf("%s ", argv[optind++]);
		printf("\n");
	}

	return 0;
}

#endif