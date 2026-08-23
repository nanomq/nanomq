#include "include/broker.h"
#include "tests_api.h"


int
main()
{
nng_thread *nmq;
	pid_t       pid_sub_nmq;
	conf *conf      = NULL;
	FILE *p_pub_nmq = NULL;

	int buf_size = 128;
	int outfp_nmq;
	char buf_nmq[buf_size];
	memset(buf_nmq, 0, buf_size);
	const char *test_port = test_env_test_port_text();
	char anon_cmd[192];

	if (!test_env_has_executable("mosquitto_sub") ||
	    !test_env_has_executable("mosquitto_pub")) {
		fprintf(stderr, "skip: mosquitto_sub and mosquitto_pub are required\n");
		return 0;
	}

	conf = get_test_conf(AUTH_ANON_CONF);
	assert(conf != NULL);
	nng_thread_create(&nmq, (void *) broker_start_with_conf, (void *) conf);
	nng_msleep(1000);

	snprintf(anon_cmd, sizeof(anon_cmd),
	    "mosquitto_sub -h 127.0.0.1 -p %s -t 'test/#' -V mqttv5 -W 2 > /dev/null 2>&1",
	    test_port);
	int anon_rv = system(anon_cmd);

	assert(WIFEXITED(anon_rv));
	assert(WEXITSTATUS(anon_rv) != 0);
	nng_msleep(500);
	char *cmd = "/bin/mosquitto_sub";
	char *cmd_sub_nmq[] = {
	    "mosquitto_sub", "-h", "127.0.0.1", "-p", (char *) test_port,
	    "-t", "test/#", "-V", "mqttv5", "-q", "2", 
	    "-u", "admin", "-P", "public",
	    NULL
	};

	pid_sub_nmq = popen_with_cmd(&outfp_nmq, cmd_sub_nmq, cmd);
	nng_msleep(2000);

	char cmd_pub_nmq[160];
	snprintf(cmd_pub_nmq, sizeof(cmd_pub_nmq),
	    "mosquitto_pub -h 127.0.0.1 -p %s -t test/anon -m 'message-to-nmq' -u admin -P public",
	    test_port);
	p_pub_nmq = popen(cmd_pub_nmq, "r");
	pclose(p_pub_nmq);


	assert(read(outfp_nmq, buf_nmq, buf_size) != -1);
	printf("get the msg in nmq:%s\n", buf_nmq);
	assert(strncmp(buf_nmq, "message-to-nmq", 14) == 0);

	kill(pid_sub_nmq, SIGKILL);
	close(outfp_nmq);
    nng_msleep(2000); 

    nng_msleep(2000); 
	broker_stop_for_test();
	nng_thread_destroy(nmq);

	return 0;
}
