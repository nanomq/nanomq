#include <stdio.h>
#include <assert.h>
#include <signal.h>
#include <unistd.h>

#include "include/broker.h"
#include "tests_api.h"

int
main()
{
	int rv = 0;

	char *cmd_sub_emqx = "mosquitto_sub -h broker.emqx.io -p 1883 -t forward1/test";
	char *cmd_sub_nmq = "mosquitto_sub -h 127.0.0.1 -p 1881 -t recv/topic1";
	char *cmd_pub_nmq = "mosquitto_pub -h 127.0.0.1 -p 1881 -t forward1/test -m message-to-emqx";
	char *cmd_pub_emqx = "mosquitto_pub -h broker.emqx.io -p 1883 -t recv/topic1 -m message-to-nmq";

	nng_thread *nmq;
	FILE       *p_sub_emqx = NULL;
	FILE       *p_sub_nmq  = NULL;
	conf       *conf       = NULL;

	int buf_size = 128;
	char buf[buf_size];
	char buf1[buf_size];

	// create nmq thread
	conf = get_test_conf();
	assert(conf != NULL);
	nng_thread_create(&nmq, broker_start_with_conf, conf);
	nng_msleep(50); // wait a while before sub

	// pipe to sub
	p_sub_emqx = popen(cmd_sub_emqx, "r");
	p_sub_nmq = popen(cmd_sub_nmq, "r");
	nng_msleep(1000); // pub should be slightly behind sub
	// pipe to pub
	popen(cmd_pub_nmq, "r");
	fgets(buf, buf_size, p_sub_emqx);
	// printf("buf:%s", buf);
	assert(strncmp(buf, "message-to-emqx", 15) == 0);

	popen(cmd_pub_emqx, "r");
	fgets(buf1, buf_size, p_sub_nmq);
	// printf("buf1:%s", buf1);
	assert(strncmp(buf1, "message-to-nmq", 14) == 0);

	nng_thread_destroy(nmq);

	return 0;
}