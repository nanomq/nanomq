//
// Copyright 2023 NanoMQ Team, Inc. <jaylin@emqx.io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "include/broker.h"
#include "tests_api.h"

#ifndef NANO_PLATFORM_WINDOWS
#include <sys/select.h>
#endif

static bool
wait_for_tcp_listener(uint16_t port, int timeout_ms)
{
#ifndef NANO_PLATFORM_WINDOWS
	int waited = 0;

	while (waited < timeout_ms) {
		int                fd;
		struct sockaddr_in addr;

		fd = socket(AF_INET, SOCK_STREAM, 0);
		if (fd >= 0) {
			memset(&addr, 0, sizeof(addr));
			addr.sin_family      = AF_INET;
			addr.sin_port        = htons(port);
			addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
			if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)) == 0) {
				close(fd);
				return true;
			}
			close(fd);
		}
		nng_msleep(50);
		waited += 50;
	}
#else
	(void) port;
	(void) timeout_ms;
#endif
	fprintf(stderr, "[FAIL] websocket listener 127.0.0.1:%u was not ready\n",
	    port);
	return false;
}

static bool
wait_for_text(int fd, const char *needle, char *output, size_t output_size,
    int timeout_ms)
{
#ifndef NANO_PLATFORM_WINDOWS
	int    waited = 0;
	size_t used   = 0;

	if (fd < 0 || needle == NULL || output == NULL || output_size < 2) {
		return false;
	}
	output[0] = '\0';
	while (waited < timeout_ms) {
		fd_set         readfds;
		struct timeval timeout = { 0, 50000 };
		char           chunk[128];
		ssize_t        n;

		FD_ZERO(&readfds);
		FD_SET(fd, &readfds);
		if (select(fd + 1, &readfds, NULL, NULL, &timeout) < 0) {
			if (errno == EINTR) {
				continue;
			}
			break;
		}
		waited += 50;
		if (!FD_ISSET(fd, &readfds)) {
			continue;
		}
		n = read(fd, chunk, sizeof(chunk) - 1);
		if (n <= 0) {
			break;
		}
		chunk[n] = '\0';
		if (used + (size_t) n >= output_size) {
			size_t keep = output_size - 1;
			size_t drop = used + (size_t) n - keep;

			if (drop < used) {
				memmove(output, output + drop, used - drop);
				used -= drop;
			} else {
				used = 0;
			}
		}
		if (n > 0) {
			size_t copy = (size_t) n;
			if (used + copy >= output_size) {
				copy = output_size - used - 1;
			}
			memcpy(output + used, chunk, copy);
			used += copy;
			output[used] = '\0';
			if (strstr(output, needle) != NULL ||
			    strstr(chunk, needle) != NULL) {
				return true;
			}
		}
	}
#else
	(void) fd;
	(void) needle;
	(void) output;
	(void) output_size;
	(void) timeout_ms;
#endif
	fprintf(stderr, "[FAIL] MQTTX did not emit %s within %dms\n", needle,
	    timeout_ms);
	return false;
}

int
main()
{
	int rv = 0;

	if (!test_env_allows_network_binds()) {
		fprintf(stderr, "skip: test environment disallows listening sockets\n");
		return 0;
	}
	char *mqttx_cmd = NULL;
	if (test_env_has_executable("mqttx")) {
		mqttx_cmd = "mqttx";
	} else if (test_env_has_executable("mqttx_cli")) {
		mqttx_cmd = "mqttx_cli";
	} else {
		fprintf(stderr, "skip: mqttx or mqttx_cli not found in PATH\n");
		return 0;
	}

	char *cmd   = mqttx_cmd;
	char *arg_pub[] = { mqttx_cmd, "pub", "-h", "127.0.0.1", "-p",
		"8083", "-t", "topic1", "-m", "message", "-l", "ws", NULL };
	// pipe to sub
	char *arg_sub[] = { mqttx_cmd, "sub", "-t", "topic1", "-h",
		"127.0.0.1", "-p", "8083", "-l", "ws", NULL };

	nng_thread *nmq;
	conf       *nmq_conf;
	pid_t       pid_sub;
	pid_t       pid_pub;

	int buf_size = 128;
	char bufsub[buf_size];
	char readiness[buf_size];
	char bufpub[buf_size];
	int  infp, outfp;

	nmq_conf = get_test_conf(ALL_FEATURE_CONF);
	assert(nmq_conf != NULL);

	// create nmq thread
	assert(nng_thread_create(&nmq, (void *) broker_start_with_conf,
	    (void *) nmq_conf) == 0);
	assert(wait_for_tcp_listener(8083, 8000));

	pid_sub = popen_sub_with_cmd_nonblock(&outfp, arg_sub, cmd);
	assert(pid_sub > 0);
	assert(wait_for_text(outfp, "Subscribed to topic1", readiness,
	    sizeof(readiness), 8000));
	// pipe to pub
	pid_pub   = popen_with_cmd(&infp, arg_pub, cmd);
	assert(pid_pub > 0);

	assert(wait_for_text(outfp, "message", bufsub, sizeof(bufsub), 8000));

	(void) bufpub;
	fprintf(stderr, "websocket message received: %s\n", bufsub);

	kill(pid_sub, SIGKILL);
	kill(pid_pub, SIGKILL);
	close(infp);
	close(outfp);
	waitpid(pid_sub, NULL, 0);
	waitpid(pid_pub, NULL, 0);

	broker_stop_for_test();
	nng_thread_destroy(nmq);

	return 0;
}
