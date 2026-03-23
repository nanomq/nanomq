#include <poll.h>
#include "include/broker.h"
#include "tests_api.h"

int
main()
{
	char *cmd = "/bin/mosquitto_sub";

	char *cmd_sub_emqx[] = { "mosquitto_sub", "-h", "broker.emqx.io", "-p",
		"1883", "-t", "forward3/test/ci", "-V", "mqttv5", "-q", "2",
		NULL };
	char *cmd_sub_emqx2[] = { "mosquitto_sub", "-h", "broker.emqx.io",
		"-p", "1883", "-t", "forward3/test/private", "-V", "mqttv5",
		"-q", "2", NULL };

	char *cmd_pub_nmq =
	    "mosquitto_pub -h 127.0.0.1 -p 1881 -t forward3/test/ci -m "
	    "message-to-emqx -V mqttv5 -q 2";
	char *cmd_pub_nmq3 =
	    "mosquitto_pub -h 127.0.0.1 -p 1881 -t forward3/test/private -m "
	    "message-to-emqx -V mqttv5 -q 2";

	nng_thread *nmq;
	pid_t       pid_sub_emqx;
	pid_t       pid_sub_emqx2;
	conf       *conf       = NULL;
	FILE       *p_pub_nmq  = NULL;
	FILE       *p_pub_nmq2 = NULL;

	int  buf_size = 128;
	int  outfp_emqx;
	int  outfp_emqx2;
	char buf_emqx[buf_size];
	char buf_emqx2[buf_size];
	memset(buf_emqx, 0, buf_size);
	memset(buf_emqx2, 0, buf_size);

	// create nmq thread
	conf = get_test_conf(BRIDGE_CONF);
	assert(conf != NULL);
	nng_thread_create(
	    &nmq, (void *) broker_start_with_conf, (void *) conf);
	nng_msleep(1000); // wait a while before sub
	pid_sub_emqx =
	    popen_sub_with_cmd_nonblock(&outfp_emqx, cmd_sub_emqx, cmd);
	pid_sub_emqx2 =
	    popen_sub_with_cmd_nonblock(&outfp_emqx2, cmd_sub_emqx2, cmd);
  nng_msleep(2000);  
  p_pub_nmq  = popen(cmd_pub_nmq, "r");  
  p_pub_nmq2 = popen(cmd_pub_nmq3, "r");  
  struct pollfd allowed = { .fd = outfp_emqx, .events = POLLIN };  
  assert(poll(&allowed, 1, 5000) == 1);  
  int allowed_n = (int) read(outfp_emqx, buf_emqx, buf_size - 1);  
  assert(allowed_n > 0);  
  buf_emqx[allowed_n] = '\0';  
  printf("get the msg in emqx: %s\n", buf_emqx);  
  assert(strncmp(buf_emqx, "message-to-emqx", 15) == 0);  
  struct pollfd excluded = { .fd = outfp_emqx2, .events = POLLIN };  
  assert(poll(&excluded, 1, 1000) == 0);  

	kill(pid_sub_emqx, SIGKILL);
	kill(pid_sub_emqx2, SIGKILL);
	pclose(p_pub_nmq);
	pclose(p_pub_nmq2);
	close(outfp_emqx);
	close(outfp_emqx2);
	nng_thread_destroy(nmq);

	return 0;
}