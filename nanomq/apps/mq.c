//
// Copyright 2021 NanoMQ Team, Inc. <jaylin@emqx.io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//
#include "mq.h"
#include "include/nanomq.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#if defined(MQ)
#include <sys/resource.h>
#include <mqueue.h>

#define FILEMODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP)
struct mq_attr attr;

int
mqcreate_debug(int argc, char **argv)
{
	int   c, flags;
	mqd_t mqd;

	flags = O_RDWR | O_CREAT;
	while ((c = getopt(argc, argv, "em:z:")) !=
	    -1) { //处理参数，带冒号的表示后面有参数的
		switch (c) {
		case 'e':
			flags |= O_EXCL;
			printf("the optind is :%d\n", optind);
			break;
		case 'm':
			attr.mq_maxmsg = atol(optarg);
			printf("the optind is :%d\n", optind);
			break;
		case 'z':
			attr.mq_msgsize = atol(optarg);
			printf("the optind is :%d\n", optind);
			break;
		}
	}
	if (optind != argc - 1) {
		debug_msg(
		    "usage: mqcreate [-e] [-m maxmsg -z msgsize] <name>");
		exit(0);
	}

	if ((attr.mq_maxmsg != 0 && attr.mq_msgsize == 0) ||
	    (attr.mq_maxmsg == 0 && attr.mq_msgsize != 0)) {
		debug_msg("must specify both -m maxmsg and -z msgsize");
		exit(0);
	}

	mqd = mq_open(argv[optind], flags, FILEMODE,
	    (attr.mq_maxmsg != 0) ? &attr : NULL);
	debug_msg("%d  %d", mqd, errno);
	mq_close(mqd);
	return 0;
}

int
mqreceive_debug(int argc, char **argv)
{
	int             flags;
	mqd_t           mqd;
	ssize_t         n;
	unsigned int    prio;
	char *          buff;
	struct mq_attr  attr;
	struct timespec abs_timeout;
	flags = O_RDONLY;
	clock_gettime(CLOCK_REALTIME, &abs_timeout);
	abs_timeout.tv_sec += 4;

	if (optind != argc - 1) {
		debug_msg("usage: mqreceive <name>");
		exit(0);
	}

	mqd = mq_open(argv[optind], flags);
	mq_getattr(mqd, &attr);

	buff = malloc(attr.mq_msgsize);

	// n = mq_receive(mqd, buff, attr.mq_msgsize, &prio);
	debug_msg("%ld", abs_timeout.tv_sec);
	n = (mq_timedreceive(mqd, buff, attr.mq_msgsize, &prio, &abs_timeout));
	mq_close(mqd);
	debug_msg("read %ld bytes, priority = %u buffer = %s\n", (long) n,
	    prio, buff);
	free(buff);
	return 0;
}

int
mqsend_debug(int argc, char **argv)
{
	mqd_t        mqd;
	char *       ptr;
	unsigned int prio;

	if (argc != 4) {
		printf("usage: mqsend <name> <bytes> <priority>");
		exit(0);
	}
	ptr  = argv[2];
	prio = atoi(argv[3]);

	if ((mqd = mq_open(argv[1], O_WRONLY)) == -1) {
		printf("open error");
		exit(0);
	}
	// ptr = calloc(len, sizeof(char));

	mq_send(mqd, ptr, strlen(argv[2]), prio);
	return 0;
}

int
dashboard_data_sync(int argc, char **argv)
{
	mqd_t mqd;
	char  buff[64];

	srand((unsigned) time(NULL));
	if (argc != 1) {
		printf("usage:sync <type:post/cache> ");
		exit(0);
	}
	return 0;
}

#endif
