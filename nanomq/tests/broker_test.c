#include "include/broker.h"
#include "tests_api.h"

int
main()
{
	int rv = 0;

	char *cmd = "/bin/mosquitto_sub";
	// char *cmd_sub = "mosquitto_sub -h 127.0.0.1 -p 1883 -t topic1 -t topic2 -U topic2 -q 2";
	char *cmd_pub = "mosquitto_pub -h 127.0.0.1 -p 1883 -t topic1 -m message -q 2";

	// char *cmd_sub = "mosquitto_sub -h 116.205.239.134 -p 1883 -t topic -q 1";
	// char *cmd_pub = "mosquitto_pub -h 116.205.239.134 -p 1883 -t topic -m massage -q 1";

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
	char *arg[] = { "mosquitto_sub", "-t", "topic1", "-t", "topic2", "-U",
		"topic2", "-h", "127.0.0.1", "-p", "1883", "-q", "2", NULL };

	pid_sub = popen_with_cmd(&outfp, arg, cmd);
	nng_msleep(50); // pub should be slightly behind sub
	// pipe to pub
	p_pub   = popen(cmd_pub, "r");

	// check recv msg
	assert(read(outfp, buf, buf_size) != -1);
	assert(strncmp(buf, "message", 7) == 0);

	kill(pid_sub, SIGKILL);
	pclose(p_pub);
	close(outfp);

	assert(broker_dflt(0, NULL) == 0);
	nng_thread_destroy(nmq);

	return 0;
}