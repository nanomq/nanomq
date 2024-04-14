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

	char *cmd_pub = "mqttx_cli pub -h 127.0.0.1 -p 8083 -t topic1 -m message -q 2 -l ws";

	nng_thread *nmq;
	pid_t pid_sub;
	FILE *p_pub = NULL;

	int buf_size = 128;
	char buf[buf_size];
	int infp, outfp;

	// create nmq thread
	nng_thread_create(&nmq, (void *) broker_start_with_conf, NULL);
	nng_msleep(50); // wait a while before sub

	// pipe to sub
	char *arg[] = { "mqttx_cli", "sub", "-t", "topic", "-h", "127.0.0.1",
		"-p", "8083", "-q", "2", "-l", "ws", NULL };
	char *cmd   = "/bin/mqttx_cli";

	pid_sub = popen_sub_with_cmd(&outfp, arg, cmd);
	nng_msleep(50); // pub should be slightly behind sub
	// pipe to pub
	p_pub   = popen(cmd_pub, "r");

	// check recv msg
	assert(read(outfp, buf, buf_size) != -1);
	assert(strncmp(buf, "message", 7) == 0);

	kill(pid_sub, SIGKILL);
	pclose(p_pub);
	close(outfp);

	nng_thread_destroy(nmq);

	return 0;
}