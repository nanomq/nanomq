#include "tests_api.h"

int
main(int argc, char **argv)
{
	if (!test_env_allows_network_binds() || !test_env_allows_port_bind(8888)) {
		fprintf(stderr, "skip: test environment disallows listening sockets\n");
		return 0;
	}
	if (!test_env_has_executable("mosquitto_pub")) {
		fprintf(stderr,
		    "skip: required MQTT clients not found in PATH\n");
		return 0;
	}

	char cmd_pub[192];
	snprintf(cmd_pub, sizeof(cmd_pub),
	    "mosquitto_pub -h 127.0.0.1 -p %s -t topic1 -m message -q 2 -i wbhk_client_id",
	    test_env_test_port_text());
	int         rv   = 0;
	nng_thread *inproc_thr = NULL;
	uint16_t    port = 8888;
	nng_thread *nmq       = NULL;
	FILE       *p_pub = NULL;
	conf       *conf;

	// start the RESTful http server thread
	int thread_rv = nng_thread_create(&inproc_thr, test_inproc_server, NULL);
	if (thread_rv != 0) {
		fatal("cannot start inproc server", thread_rv);
	}
	test_rest_start(port);

	conf = get_webhook_conf();
	if (nng_thread_create(&nmq, (void *) broker_start_with_conf, (void *) conf) != 0) {
		rv = -1;
		goto cleanup;
	}
	nng_msleep(800); // wait a while for broker to init.
	                 // webhook_server_start() will msleep for 500ms.

	// pipe for pub to trigger webhook
	p_pub = popen(cmd_pub, "r");
	if (p_pub == NULL) {
		rv = -1;
		goto cleanup;
	}
	if (pclose(p_pub) != 0) {
		rv = -1;
	}
	p_pub = NULL;
	if (!wait_for_webhook_message_count(5, WEBHOOK_MESSAGE_TIMEOUT_MS, 50)) {
		rv = -1;
	}

cleanup:
	if (p_pub != NULL) {
		pclose(p_pub);
	}
	if (nmq != NULL) {
		broker_stop_for_test();
		nng_thread_destroy(nmq);
	}
	if (inproc_thr != NULL) {
		test_inproc_stop();
		nng_thread_destroy(inproc_thr);
	}
	return rv;
}
