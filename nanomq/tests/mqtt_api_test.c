//
// Copyright 2023 NanoMQ Team, Inc. <jaylin@emqx.io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "include/mqtt_api.h"
#include "nng/supplemental/nanolib/log.h"
#include "tests_api.h"

static conf_log *
get_conf_log()
{
	conf_log *log;
	log = nng_zalloc(sizeof(conf_log));
	assert(log != NULL);
	log->level = NNG_LOG_WARN;
	log->file  = NULL;
	log->dir   = "/tmp/";
	log->type  = LOG_TO_CONSOLE | LOG_TO_FILE | LOG_TO_SYSLOG;
	log->fp    = NULL;

	log->abs_path        = NULL;
	log->rotation_sz_str = NULL;
	log->rotation_sz     = 10 * 1024;
	log->rotation_count  = 5;

	return log;
}

static void
free_conf_log(conf_log *log)
{
	nng_strfree(log->file);
	nng_strfree(log->abs_path);
	nng_free(log, sizeof(conf_log));
}

static int
test_log()
{
	conf_log *log;

	log = get_conf_log();
	assert(log_init(log) == 0);
	assert(log_fini(log) == 0);
	free_conf_log(log);

	return 0;
}

static int
pipe_get()
{
	int         rv;
	nng_socket  reqsock;
	nng_socket  repsock;
	const char *addr = "tcp://127.0.0.1:1883";

	nng_listener l          = NNG_LISTENER_INITIALIZER;
	nng_dialer   d          = NNG_DIALER_INITIALIZER;
	nng_pipe     p          = NNG_PIPE_INITIALIZER;
	nng_msg     *send       = NULL;
	nng_msg     *recv       = NULL;
	char        *local_addr = NULL;
	uint16_t     local_port;

	assert(nng_req_open(&reqsock) == 0);
	assert(nng_rep_open(&repsock) == 0);

	rv = nng_listener_create(&l, repsock, addr);
	assert(rv == 0);
	if ((rv = nng_listener_start(l, 0)) != 0) {
		nng_listener_close(l);
		return (rv);
	}

	rv = nng_dialer_create(&d, reqsock, addr);
	assert(rv == 0);
	if ((rv = nng_dialer_start(d, 0)) != 0) {
		nng_dialer_close(d);
		return (rv);
	}

	nng_msleep(200); // listener may be behind slightly

	assert(nng_msg_alloc(&send, 0) == 0);
	assert(nng_msg_append(send, "ping", 5) == 0);
	assert(nng_sendmsg(reqsock, send, 0) == 0);
	assert(nng_recvmsg(repsock, &recv, 0) == 0);
	assert(recv != NULL);
	assert(nng_msg_len(recv) == 5);
	assert(strcmp(nng_msg_body(recv), "ping") == 0);
	p = nng_msg_get_pipe(recv);
	assert(nng_pipe_id(p) > 0);

	local_addr = nano_pipe_get_local_address(p);
	local_port = nano_pipe_get_local_port(p);
	assert(strncmp(local_addr, "127.0.0.1", 9) == 0);
	assert(local_port == 1883);

	nng_msg_free(recv);
	nng_strfree(local_addr);

	nng_close(reqsock);
	nng_close(repsock);

	return 0;
}

static int
pipe_get6()
{
	int         rv;
	nng_socket  reqsock;
	nng_socket  repsock;
	const char *addr = "tcp://[::1]:1884";

	nng_listener l    = NNG_LISTENER_INITIALIZER;
	nng_dialer   d    = NNG_DIALER_INITIALIZER;
	nng_pipe     p    = NNG_PIPE_INITIALIZER;
	nng_msg     *send = NULL;
	nng_msg     *recv = NULL;
	uint16_t     local_port;
	uint8_t     *local_addr6;

	assert(nng_req_open(&reqsock) == 0);
	assert(nng_rep_open(&repsock) == 0);

	rv = nng_listener_create(&l, repsock, addr);
	assert(rv == 0);
	if ((rv = nng_listener_start(l, 0)) != 0) {
		nng_listener_close(l);
		return (rv);
	}

	rv = nng_dialer_create(&d, reqsock, addr);
	assert(rv == 0);
	if ((rv = nng_dialer_start(d, 0)) != 0) {
		nng_dialer_close(d);
		return (rv);
	}

	nng_msleep(200); // listener may be behind slightly

	assert(nng_msg_alloc(&send, 0) == 0);
	assert(nng_msg_append(send, "ping", 5) == 0);
	assert(nng_sendmsg(reqsock, send, 0) == 0);
	assert(nng_recvmsg(repsock, &recv, 0) == 0);
	assert(recv != NULL);
	assert(nng_msg_len(recv) == 5);
	assert(strcmp(nng_msg_body(recv), "ping") == 0);
	p = nng_msg_get_pipe(recv);
	assert(nng_pipe_id(p) > 0);

	local_addr6 = nano_pipe_get_local_address6(p);
	local_port  = nano_pipe_get_local_port6(p);
	assert(*local_addr6 == 0);
	assert(local_port == 1884);

	nng_msg_free(recv);
	nng_free(local_addr6, sizeof(uint8_t) * 16);

	nng_close(reqsock);
	nng_close(repsock);

	return 0;
}

static int
test_pipe_get()
{
	assert(pipe_get() == 0);
	assert(pipe_get6() == 0);

	return 0;
}

int
main()
{
	int rv = 0;

	assert(test_log() == 0);

	assert(test_pipe_get() == 0);

	return 0;
}