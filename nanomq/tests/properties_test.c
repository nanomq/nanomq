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

	char *cmd_pub = "mosquitto_pub -h 127.0.0.1 -p 1881 -t topic1 -m "
	                "message -q 2 -V mqttv5"
	                " -D CONNECT authentication-data 101"
	                " -D CONNECT authentication-method auth-mtd"
	                " -D CONNECT maximum-packet-size 512"
	                " -D CONNECT receive-maximum 16"
	                " -D CONNECT request-problem-information 1"
	                " -D CONNECT request-response-information 0"
	                " -D CONNECT session-expiry-interval 32"
	                " -D CONNECT topic-alias-maximum 16"
	                " -D CONNECT user-property c-up-n c-up-v"
	                " -D PUBLISH content-type ct"
	                " -D PUBLISH correlation-data 010101"
	                " -D PUBLISH message-expiry-interval 32"
	                " -D PUBLISH payload-format-indicator 8"
	                " -D PUBLISH response-topic response-t"
	                " -D PUBLISH topic-alias 16"
	                " -D PUBLISH user-property p-up-n p-up-v"
	                " -D DISCONNECT session-expiry-interval 32"
	                " -D DISCONNECT user-property d-up-n d-up-v"
	                " -D WILL content-type ct-tp"
	                " -D WILL correlation-data 0100101"
	                " -D WILL message-expiry-interval 32"
	                " -D WILL payload-format-indicator 8"
	                " -D WILL response-topic resp-tp"
	                " -D WILL user-property w-up-n w-up-v"
	                " -D WILL will-delay-interval 32";

	nng_thread *nmq;
	pid_t pid_sub;
	FILE *p_pub = NULL;
	conf       *conf;

	int buf_size = 128;
	char buf[buf_size];
	int infp, outfp;

	// create nmq thread
	conf = get_test_conf(ALL_FEATURE_CONF);
	assert(conf != NULL);
	nng_thread_create(&nmq, (void *) broker_start_with_conf, (void *) conf);
	nng_msleep(500); // wait a while before sub

	// pipe to sub
	char *arg[] = { "mosquitto_sub", "-t", "topic1", "-t", "topic2", "-U",
		"topic2", "-h", "127.0.0.1", "-p", "1881", "-q", "2", "-V",
		"mqttv5",
		// regard as invalid sub and unsub packet
		// "-D", "SUBSCRIBE", "user-property", "s-up-n",
		// "s-up-v", "-D", "UNSUBSCRIBE", "user-property", "u-up-n",
		// "u-up-v",
		NULL };

	pid_sub = popen_with_cmd(&outfp, arg, "/bin/mosquitto_sub");
	nng_msleep(1000); // pub should be slightly behind sub

	// pipe to pub
	p_pub   = popen(cmd_pub, "r");

	// check recv msg
	nng_msleep(2000);
	assert(read(outfp, buf, buf_size) != -1);
	log_warn("what we got:%s", buf);
	assert(strncmp(buf, "message", 7) == 0);

	kill(pid_sub, SIGKILL);
	pclose(p_pub);
	close(outfp);

	nng_thread_destroy(nmq);

	return 0;
}