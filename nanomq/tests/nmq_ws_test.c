//
// Copyright 2023 NanoMQ Team, Inc. <jaylin@emqx.io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "include/broker.h"
#include "tests_api.h"

int
main()
{
	int rv = 0;

	char *cmd   = "/bin/mqttx_cli";
	char *arg_pub[] = { "mqttx_cli", "pub", "-h", "127.0.0.1", "-p",
		"8083", "-t", "topic1", "-m", "message", "-l", "ws", NULL };
	// pipe to sub
	char *arg_sub[] = { "mqttx_cli", "sub", "-t", "topic1", "-h",
		"127.0.0.1", "-p", "8083", "-l", "ws", NULL };

	nng_thread *nmq;
	pid_t       pid_sub;
	pid_t       pid_pub;

	int buf_size = 128;
	char bufsub[buf_size];
	char bufpub[buf_size];
	int  infp, outfp;

	// create nmq thread
	nng_thread_create(&nmq, (void *) broker_start_with_conf, NULL);
	nng_msleep(50); // wait a while before sub

	pid_sub = popen_with_cmd(&outfp, arg_sub, cmd);
	nng_msleep(50); // pub should be slightly behind sub
	// pipe to pub
	pid_pub   = popen_with_cmd(&infp, arg_pub, cmd);

	// // check recv msg
	assert(read(infp, bufpub, buf_size) != -1);
	assert(read(outfp, bufsub, buf_size) != -1);

	printf("bufpub:%s\n",bufpub);
	printf("bufsub:%s\n",bufsub);
	// assert(strncmp(buf, "message", 7) == 0);

	kill(pid_sub, SIGKILL);
	kill(pid_pub, SIGKILL);
	close(infp);
	close(outfp);

	nng_thread_destroy(nmq);

	return 0;
}