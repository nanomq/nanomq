#include "include/broker.h"
#include "tests_api.h"

int
main()
{
	int rv = 0;

	char *cmd = "/bin/mosquitto_sub";
	char *cmd_pub =
	    "mosquitto_pub -h 127.0.0.1 -p 8883 -t topic1 -m message -q 2 "
	    "--cafile ../../../etc/certs/cacert.pem --insecure";

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
	nng_msleep(5000); // wait a while before sub

	// pipe to sub
	char *arg[] = { "mosquitto_sub", "-t", "topic1", "-t", "topic2", "-U",
		"topic2", "-h", "127.0.0.1", "-p", "8883", "-q", "2",
		"--cafile", "../../../etc/certs/cacert.pem", "--insecure",
		NULL };

	pid_sub = popen_with_cmd(&outfp, arg, cmd);
	nng_msleep(200); // pub should be slightly behind sub
	// pipe to pub
	p_pub   = popen(cmd_pub, "r");

	// check recv msg
	nng_msleep(100);
	assert(read(outfp, buf, buf_size) != -1);
	printf("what we got:%s", buf);
	assert(strncmp(buf, "message", 7) == 0);

	kill(pid_sub, SIGKILL);
	pclose(p_pub);
	close(outfp);

	nng_thread_destroy(nmq);

	return 0;
}