#include "include/broker.h"
#include "tests_api.h"

int
main()
{
	/* subs are configured as followed:
	recv/topic1: rap 0
	recv/topic2: rap 1, rh 0
	cmd/topic1: rap 1, rh 1
	cmd/topic2: rap 1, rh 2
	*/
	char *cmd_sub_nmq_rap0[] = {"mosquitto_sub", "-h", "127.0.0.1", "-p", "1881", "-t", "recv/topic1", "-V", "mqttv5", "-q", "2", "-i", "id-nmq-test", NULL};
	char *cmd_sub_nmq_rh0[] = {"mosquitto_sub", "-h", "127.0.0.1", "-p", "1881", "-t", "recv/topic2", "-V", "mqttv5", "-q", "2", "-i", "id-nmq-test", NULL};
	char *cmd_sub_nmq_rh1[] = {"mosquitto_sub", "-h", "127.0.0.1", "-p", "1881", "-t", "cmd/topic1", "-V", "mqttv5", "-q", "2", "-i", "id-nmq-test", NULL};
	char *cmd_sub_nmq_rh2[] = {"mosquitto_sub", "-h", "127.0.0.1", "-p", "1881", "-t", "cmd/topic2", "-V", "mqttv5", "-q", "2", "-i", "id-nmq-test", NULL};

	// bridge client resub can not parse rh, so we can not test rh1 for now.
	char *cmd_resub = "curl -i --location "
	            "'http://localhost:8081/api/v4/bridges/sub/emqx' "
	            "--basic -u admin_test:pw_test -d '{\"data\": "
	            "{\"subscription\": [{\"topic\": \"cmd/topic1\", \"retain_handling\": 1}]}}'";

	char *cmd_pub_emqx_rap0 = "mosquitto_pub -h broker.emqx.io -p 1883 -t recv/topic1 -m message-to-nmq -V mqttv5 -q 2 --retain";
	char *cmd_pub_emqx_rh0 = "mosquitto_pub -h broker.emqx.io -p 1883 -t recv/topic2 -m message-to-nmq -V mqttv5 -q 2 --retain";
	char *cmd_pub_emqx_rh1 = "mosquitto_pub -h broker.emqx.io -p 1883 -t cmd/topic1 -m message-to-nmq -V mqttv5 -q 2 --retain";
	char *cmd_pub_emqx_rh2 = "mosquitto_pub -h broker.emqx.io -p 1883 -t cmd/topic2 -m message-to-nmq -V mqttv5 -q 2 --retain";

	nng_thread *nmq;
	pid_t       pid_sub_nmq_rap0;
	pid_t       pid_sub_nmq_rh0;
	pid_t       pid_sub_nmq_rh1;
	pid_t       pid_sub_nmq_rh1_re;
	pid_t       pid_sub_nmq_rh2;
	conf *conf      = NULL;
	FILE *p_pub_emqx_rap0 = NULL;
	FILE *p_pub_emqx_rh0 = NULL;
	FILE *p_pub_emqx_rh1 = NULL;
	FILE *p_pub_emqx_rh2 = NULL;


	int buf_size = 128;
	int  outfp_nmq_rap0;
	int  outfp_nmq_rh0;
	int  outfp_nmq_rh1;
	int  outfp_nmq_rh2;
	char buf_rap0[buf_size];
	char buf_rh0[buf_size];
	char buf_rh1[buf_size];
	char buf_rh2[buf_size];
	memset(buf_rap0, 0, buf_size);
	memset(buf_rh0, 0, buf_size);
	memset(buf_rh1, 0, buf_size);
	memset(buf_rh2, 0, buf_size);

	// pub the retain msgs.
	p_pub_emqx_rap0 = popen(cmd_pub_emqx_rap0, "r");
	p_pub_emqx_rh0 = popen(cmd_pub_emqx_rh0, "r");
	p_pub_emqx_rh1 = popen(cmd_pub_emqx_rh1, "r");
	p_pub_emqx_rh2 = popen(cmd_pub_emqx_rh2, "r");

	// create nmq thread
	conf = get_test_conf(BRIDGE_CONF);
	assert(conf != NULL);
	nng_thread_create(&nmq, (void *) broker_start_with_conf, (void *) conf);
	nng_msleep(500); // wait a while before sub
	pid_sub_nmq_rap0 = popen_sub_with_cmd(&outfp_nmq_rap0, cmd_sub_nmq_rap0);
	// TODO: better check the retain flag
	assert(read(outfp_nmq_rap0, buf_rap0, buf_size) > 0);
	assert(strncmp(buf_rap0, "message-to-nmq", 14) == 0);
	memset(buf_rap0, 0, buf_size);
	pid_sub_nmq_rh0 = popen_sub_with_cmd(&outfp_nmq_rh0, cmd_sub_nmq_rh0);
	assert(read(outfp_nmq_rh0, buf_rh0, buf_size) > 0);
	assert(strncmp(buf_rh0, "message-to-nmq", 14) == 0);
	memset(buf_rh0, 0, buf_size);
	pid_sub_nmq_rh1 = popen_sub_with_cmd(&outfp_nmq_rh1, cmd_sub_nmq_rh1);
	assert(read(outfp_nmq_rh1, buf_rh1, buf_size) > 0);
	assert(strncmp(buf_rh1, "message-to-nmq", 14) == 0);
	memset(buf_rh1, 0, buf_size);

	// resub to trigger rh1. 
	popen(cmd_resub, "r");
	nng_msleep(500);
	pid_sub_nmq_rh1_re = popen_sub_with_cmd_nonblock(&outfp_nmq_rh1, cmd_sub_nmq_rh1);
	pid_sub_nmq_rh2 = popen_sub_with_cmd_nonblock(&outfp_nmq_rh2, cmd_sub_nmq_rh2);
	// consider the msg is not recvieved after 2s.
	nng_msleep(2000);
	int a = read(outfp_nmq_rh1, buf_rh1, buf_size);
	int b = read(outfp_nmq_rh2, buf_rh2, buf_size);
	printf("a=%d, b=%d\n", a, b);
	// assert(read(outfp_nmq_rh1, buf_rh1, buf_size) == 0);
	// read is supposed to return 0, may need further check.
	assert(read(outfp_nmq_rh2, buf_rh2, buf_size) == -1);

	kill(pid_sub_nmq_rap0, SIGKILL);
	kill(pid_sub_nmq_rh0, SIGKILL);
	kill(pid_sub_nmq_rh1, SIGKILL);
	kill(pid_sub_nmq_rh1_re, SIGKILL);
	kill(pid_sub_nmq_rh2, SIGKILL);
	pclose(p_pub_emqx_rap0);
	pclose(p_pub_emqx_rh0);
	pclose(p_pub_emqx_rh1);
	pclose(p_pub_emqx_rh2);
	close(outfp_nmq_rap0);
	close(outfp_nmq_rh0);
	close(outfp_nmq_rh1);
	close(outfp_nmq_rh2);
	nng_thread_destroy(nmq);

	return 0;
}