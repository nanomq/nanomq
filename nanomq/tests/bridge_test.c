#include "include/broker.h"
#include "tests_api.h"

int
main()
{
	char *cmd_sub_emqx[] = {"mosquitto_sub", "-h", "broker.emqx.io", "-p", "1883", "-t", "forward1/test", "-V", "mqttv5", NULL};
	char *cmd_sub_nmq[] = {"mosquitto_sub", "-h", "127.0.0.1", "-p", "1881", "-t", "recv/topic1", "-V", "mqttv5", NULL};

	char *cmd_pub_nmq = "mosquitto_pub -h 127.0.0.1 -p 1881 -t forward1/test -m message-to-emqx -V mqttv5";
	char *cmd_pub_emqx = "mosquitto_pub -h broker.emqx.io -p 1883 -t recv/topic1 -m message-to-nmq -V mqttv5";

	nng_thread *nmq;
	pid_t       pid_sub_nmq;
	pid_t       pid_sub_emqx;
	conf *conf      = NULL;
	FILE *p_pub_nmq = NULL;
	FILE *p_pub_emqx = NULL;

	int buf_size = 128;
	int  outfp_nmq, outfp_emqx;
	char buf_nmq[buf_size];
	char buf_emqx[buf_size];

	// create nmq thread
	conf = get_test_conf();
	assert(conf != NULL);
	nng_thread_create(&nmq, (void *) broker_start_with_conf, (void *) conf);
	nng_msleep(50); // wait a while before sub

	pid_sub_nmq = popen_sub_with_cmd(&outfp_nmq, cmd_sub_nmq);
	pid_sub_emqx = popen_sub_with_cmd(&outfp_emqx, cmd_sub_emqx);
	nng_msleep(500);
	p_pub_emqx = popen(cmd_pub_emqx, "r");
	p_pub_nmq= popen(cmd_pub_nmq, "r");
	// check recv msg
	assert(read(outfp_nmq, buf_nmq, buf_size) != -1);
	assert(strncmp(buf_nmq, "message-to-nmq", 14) == 0);
	assert(read(outfp_emqx, buf_emqx, buf_size) != -1);
	assert(strncmp(buf_emqx, "message-to-emqx", 15) == 0);

	kill(pid_sub_nmq, SIGKILL);
	kill(pid_sub_emqx, SIGKILL);
	pclose(p_pub_nmq);
	pclose(p_pub_emqx);
	close(outfp_nmq);
	close(outfp_emqx);
	nng_thread_destroy(nmq);

	return 0;
}