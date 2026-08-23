#include "include/broker.h"
#include "tests_api.h"

int
main()
{
	if (!test_env_allows_network_binds() || !test_env_allows_port_bind(8883)) {
		fprintf(stderr, "skip: test environment disallows listening sockets\n");
		return 0;
	}
	if (!test_env_supports_tls()) {
		fprintf(stderr, "skip: TLS support unavailable\n");
		return 0;
	}
	if (!test_env_supports_tls_runtime()) {
		fprintf(stderr,
		    "skip: TLS runtime not available in this test environment\n");
		return 0;
	}
	if (!test_env_has_file("../../../etc/certs/cacert.pem")) {
		fprintf(stderr, "skip: CA certificate missing for TLS tests\n");
		return 0;
	}
	if (!test_env_has_executable("mosquitto_sub") ||
	    !test_env_has_executable("mosquitto_pub")) {
		fprintf(stderr,
		    "skip: required MQTT clients not found in PATH\n");
		return 0;
	}

	int rv = 0;

	char *cmd = "mosquitto_sub";
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
	assert(p_pub != NULL);

	// check recv msg
	memset(buf, 0, buf_size);
	assert(test_env_wait_for_output(outfp, buf, buf_size, 8000, 50));
	printf("what we got:%s", buf);
	assert(strncmp(buf, "message", 7) == 0);

	test_env_kill_and_reap(pid_sub);
	pclose(p_pub);
	close(outfp);

	broker_stop_for_test();
	nng_thread_destroy(nmq);

	return 0;
}
