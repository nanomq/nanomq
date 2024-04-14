#include "include/broker.h"
#include "tests_api.h"

int
main()
{
	char *cmd = "/bin/mosquitto_sub";

	char *cmd_sub[] = {"mosquitto_sub", "-h", "127.0.0.1", "-p", "1881", "-t", "nmqtest_sub", "-V", "mqttv5", NULL};

	char *cmd_pub= "mosquitto_pub -h 127.0.0.1 -p 1881 -t nmqtest_lo -m message-to-aws -V mqttv5";

	nng_thread *nmq;
	pid_t       pid_sub;
	conf       *conf  = NULL;
	FILE       *p_pub = NULL;

	int buf_size = 128;
	int  outfp;
	char buf[buf_size];
	memset(buf, 0, buf_size);

	// create nmq thread
	conf = get_test_conf(BRIDGE_AWS_CONF);
	assert(conf != NULL);
	nng_thread_create(&nmq, (void *) broker_start_with_conf, (void *) conf);
	nng_msleep(1000); // wait a while before sub
	pid_sub = popen_with_cmd(&outfp, cmd_sub, cmd);
	nng_msleep(2000);
	p_pub = popen(cmd_pub, "r");
	// check recv msg
	assert(read(outfp, buf, buf_size) != -1);
	printf("get the msg in nmq:%s\n", buf);
	assert(strncmp(buf, "message-to-aws", 14) == 0);

	kill(pid_sub, SIGKILL);
	// pclose(p_pub);
	close(outfp);
	nng_thread_destroy(nmq);

	return 0;
}