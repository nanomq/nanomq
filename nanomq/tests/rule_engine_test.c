#include "tests_api.h"

#define RULE_HTTP_OK "HTTP/1.1 200"
#define RULE_HTTP_BAD_REQUEST "HTTP/1.1 400"

static bool
rule_response_has(const char *response, const char *status, int code)
{
	char code_text[32];

	if (response == NULL || strstr(response, status) == NULL) {
		fprintf(stderr, "[FAIL] rule API status mismatch; response: %s\n",
		    response == NULL ? "<null>" : response);
		return false;
	}
	snprintf(code_text, sizeof(code_text), "\"code\":%d", code);
	if (strstr(response, code_text) == NULL) {
		snprintf(code_text, sizeof(code_text), "\"code\": %d", code);
	}
	if (strstr(response, code_text) == NULL) {
		fprintf(stderr,
		    "[FAIL] rule API result mismatch; expected code %d; response: %s\n",
		    code, response);
		return false;
	}
	return true;
}

static bool
run_rule_request(const char *request, const char *status, int code)
{
	FILE *fd;
	char  response[8192] = { 0 };

	fd = test_env_popen(request, "r");
	if (fd == NULL) {
		fprintf(stderr, "[FAIL] failed to start rule API request\n");
		return false;
	}
	if (!test_env_read_stream_timeout(fd, response, sizeof(response), 6000, 25) ||
	    test_env_pclose_timeout(fd, 6000) == -1) {
		fprintf(stderr, "[FAIL] rule API request could not be reaped\n");
		return false;
	}
	return rule_response_has(response, status, code);
}

static bool
wait_for_rule_api(uint16_t rest_port)
{
	char request[256];

	snprintf(request, sizeof(request),
	    "curl -sS -i --basic -u admin_test:pw_test "
	    "--connect-timeout 1 --max-time 1 "
	    "'http://127.0.0.1:%hu/api/v4'", rest_port);

	for (int i = 0; i < 10; ++i) {
		FILE *fd = test_env_popen(request, "r");
		char  response[512] = { 0 };

		if (fd != NULL) {
			bool read_ok = test_env_read_stream_timeout(
			    fd, response, sizeof(response), 1000, 25);
			bool close_ok = test_env_pclose_timeout(fd, 2000) != -1;
			if (read_ok && close_ok && strstr(response, RULE_HTTP_OK) != NULL) {
				return true;
			}
		}
		nng_msleep(100);
	}
	fprintf(stderr, "[FAIL] rule API did not become ready on 127.0.0.1:%hu\n",
	    rest_port);
	return false;
}

int
main(void)
{
	char        test_port[16];
	char        rule_request[2048];
	conf       *nmq_conf = NULL;
	nng_thread *nmq      = NULL;

	if (!test_env_allows_network_binds() || !test_env_allows_port_bind(8081)) {
		fprintf(stderr, "skip: test environment disallows listening sockets\n");
		return 0;
	}
	if (!test_env_has_executable("curl")) {
		fprintf(stderr, "skip: curl not found in PATH\n");
		return 0;
	}
#ifdef SUPP_RULE_ENGINE
	if (!test_env_has_executable("mosquitto_pub") ||
	    !test_env_has_executable("mosquitto_sub")) {
		fprintf(stderr,
		    "skip: required MQTT clients not found in PATH\n");
		return 0;
	}
#endif
	snprintf(test_port, sizeof(test_port), "%s", test_env_test_port_text());

	nmq_conf = get_test_conf(ALL_FEATURE_CONF);
	assert(nmq_conf != NULL);
	assert(nng_thread_create(&nmq, (void *) broker_start_with_conf,
	    (void *) nmq_conf) == 0);
	assert(wait_for_rule_api(8081));

	snprintf(rule_request, sizeof(rule_request),
	    "curl -sS -i --basic -u admin_test:pw_test --connect-timeout 1 "
	    "--max-time 5 'http://127.0.0.1:8081/api/v4/rules' -X POST -d "
	    "'{\"rawsql\":\"select * from \\\"rule/input\\\"\","
	    "\"actions\":[{\"name\":\"repub\",\"params\":{"
	    "\"topic\":\"rule/output\",\"address\":\"mqtt-tcp://127.0.0.1:%s\","
	    "\"clean_start\":true,\"proto_ver\":4,\"keepalive\":60}}],"
	    "\"description\":\"rule-engine-test\"}'",
	    test_port);

#ifndef SUPP_RULE_ENGINE
	assert(run_rule_request(rule_request, RULE_HTTP_OK, 111));
#else
	assert(run_rule_request(rule_request, RULE_HTTP_OK, 0));
	char sub_command[256];
	char pub_command[256];
	FILE *sub;
	FILE *pub;
	char  output[256] = { 0 };

	snprintf(sub_command, sizeof(sub_command),
	    "mosquitto_sub -h 127.0.0.1 -p %s -t rule/output -q 1 -C 1 -W 8",
	    test_port);
	snprintf(pub_command, sizeof(pub_command),
	    "mosquitto_pub -h 127.0.0.1 -p %s -t rule/input -m rule_message -q 1",
	    test_port);
	sub = test_env_popen(sub_command, "r");
	assert(sub != NULL);
	nng_msleep(300);
	pub = test_env_popen(pub_command, "r");
	assert(pub != NULL);
	assert(test_env_pclose_timeout(pub, 10000) == 0);
	assert(test_env_read_stream_timeout(sub, output, sizeof(output), 9000, 25));
	assert(strstr(output, "rule_message") != NULL);
	assert(test_env_pclose_timeout(sub, 2000) == 0);
#endif

	broker_stop_for_test();
	assert(nmq != NULL);
	nng_thread_destroy(nmq);
	return 0;
}
