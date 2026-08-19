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

	conf = get_test_conf(AUTH_ANON_CONF);
	assert(conf != NULL);
	nng_thread_create(&nmq, (void *) broker_start_with_conf, (void *) conf);
	nng_msleep(1000);

	int anon_rv = system("mosquitto_sub -h 127.0.0.1 -i 'failed_one' -p 1883 -t 'test/#' -W 2 > /dev/null 2>&1");

	assert(anon_rv != 0); 
	nng_msleep(2000);
	char *cmd = "/bin/mosquitto_sub";
	char *cmd_sub_nmq[] = {
	    "mosquitto_sub", "-h", "127.0.0.1", "-u", "admin", "-P", "public", "-p", "1883", "-i", "correct_one", 
	    "-t", "test/#", "-V", "mqttv5", "-q", "2", 
	    NULL
	};

	pid_sub_nmq = popen_with_cmd(&outfp_nmq, cmd_sub_nmq, cmd);
	nng_msleep(4000);

	char *cmd_pub_nmq = "mosquitto_pub -h 127.0.0.1 -p 1883  -u 'admin' -P 'public' -t 'test/anon' -i 'pub_client' -m 'message-to-nmq'";
	p_pub_nmq = popen(cmd_pub_nmq, "r");
	nng_msleep(4000);
	pclose(p_pub_nmq);

	nng_msleep(4000);
	assert(read(outfp_nmq, buf_nmq, buf_size) != -1);
	printf("get the msg in nmq:%s\n", buf_nmq);
	nng_msleep(4000); 
	assert(strncmp(buf_nmq, "message-to-nmq", 14) == 0);

	kill(pid_sub_nmq, SIGKILL);
	close(outfp_nmq);
    nng_msleep(10000); 
	nng_thread_destroy(nmq);

	return 0;
}