//
// Copyright 2026 NanoMQ Team, Inc. <jaylin@emqx.io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

// Snapshot ownership and REST enumeration, using sequential protocol callbacks.
// No listener, network traffic, or concurrent connection churn is needed.
#include "core/nng_impl.h"
#include "core/sockimpl.h"
#include "include/rest_api.h"
#include "nng/protocol/mqtt/mqtt_parser.h"
#include "nng/protocol/mqtt/nmq_mqtt.h"
#include "nng/supplemental/nanolib/hash_table.h"
#include "nng/supplemental/nanolib/utils.h"
#include "supplemental/mqtt/mqtt_qos_db_api.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(expr)                                                          \
	do {                                                                  \
		if (!(expr)) {                                                 \
			fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expr); \
			abort();                                               \
		}                                                             \
	} while (0)

typedef struct {
	nni_pipe   *pipe;
	conn_param *cp;
} snapshot_test_pipe;

static int
test_pipe_init(void *arg, nni_pipe *pipe)
{
	snapshot_test_pipe *p = arg;
	p->pipe = pipe;
	nni_pipe_set_conn_param(pipe, p->cp);
	// Match the decoded connection ownership of a real transport.
	conn_param_clone(p->cp);
	return 0;
}

static void
test_pipe_fini(void *arg)
{
	snapshot_test_pipe *p = arg;
	if (p->pipe->nano_qos_db != NULL) {
		nni_qos_db_fini_id_hash(p->pipe->nano_qos_db);
	}
	conn_param_free(p->cp);
}

static void
test_pipe_close(void *arg)
{
	NNI_ARG_UNUSED(arg);
}

static void
test_pipe_recv(void *arg, nni_aio *aio)
{
	// No stream is attached, so receive has no completion to schedule.
	NNI_ARG_UNUSED(arg);
	NNI_ARG_UNUSED(aio);
}

static int
test_pipe_getopt(void *arg, const char *name, void *buf, size_t *sz,
    nni_opt_type type)
{
	NNI_ARG_UNUSED(arg);
	NNI_ARG_UNUSED(name);
	NNI_ARG_UNUSED(buf);
	NNI_ARG_UNUSED(sz);
	NNI_ARG_UNUSED(type);
	return NNG_ENOTSUP;
}

static nni_sp_pipe_ops test_pipe_ops = {
	.p_init   = test_pipe_init,
	.p_fini   = test_pipe_fini,
	.p_close  = test_pipe_close,
	.p_recv   = test_pipe_recv,
	.p_getopt = test_pipe_getopt,
};

static nni_sp_tran test_transport = { .tran_pipe = &test_pipe_ops };

static void
expect_event(nng_socket sock, uint8_t command)
{
	nng_msg *msg;
	CHECK(nng_recvmsg(sock, &msg, 0) == 0);
	CHECK(nng_msg_cmd_type(msg) == command);
	conn_param *cp = nng_msg_get_conn_param(msg);
	conn_param_free(cp);
	if (command == CMD_DISCONNECT_EV) {
		// Disconnect transfers the retired protocol reference as well.
		conn_param_free(cp);
	}
	nng_msg_free(msg);
}

static void
create_pipe(nni_sock *core, nng_socket sock, snapshot_test_pipe *p,
    const char *client_id)
{
	nni_listener listener = { .l_sock = core, .l_tran = &test_transport };
	memset(p, 0, sizeof(*p));
	CHECK(conn_param_alloc(&p->cp) == 0);
	conn_param_set_clientid(p->cp, client_id);
	conn_param_set_username(p->cp, "snapshot-user");
	p->cp->pro_name.body = nng_strdup("MQTT");
	CHECK(p->cp->pro_name.body != NULL);
	p->cp->pro_name.len = 4;
	p->cp->pro_ver = 5;
	p->cp->con_flag = 0x82;
	p->cp->clean_start = 1;
	p->cp->keepalive_mqtt = 60;
	CHECK(nni_pipe_create_listener(&p->pipe, &listener, p) == 0);
	// Keep the creation reference; the stack listener is no longer needed.
	p->pipe->p_listener = NULL;
	CHECK(p->pipe->p_proto_ops.pipe_start(p->pipe->p_proto_data) == 0);
	expect_event(sock, CMD_CONNACK);
}

static void
dispose_pipe(nng_socket sock, snapshot_test_pipe *p)
{
	nni_pipe_close(p->pipe);
	expect_event(sock, CMD_DISCONNECT_EV);
	nni_pipe_rele(p->pipe);
	nni_reap_drain();
}

static nng_mqtt_pipe_snapshot
snapshot(nng_socket sock)
{
	nng_mqtt_pipe_snapshot result = { 0 };
	size_t size = sizeof(result);
	CHECK(nng_socket_get(sock, NMQ_OPT_MQTT_PIPE_SNAPSHOT, &result, &size) == 0);
	CHECK(size == sizeof(result));
	return result;
}

static void
check_option_contract(nng_socket sock)
{
	nng_mqtt_pipe_snapshot empty = snapshot(sock);
	CHECK(empty.ids == NULL && empty.count == 0);
	nng_mqtt_pipe_snapshot_free(&empty);
	nng_mqtt_pipe_snapshot_free(&empty);
	nng_mqtt_pipe_snapshot_free(NULL);

	void *raw = &empty;
	CHECK(nng_socket_get_ptr(sock, NMQ_OPT_MQTT_PIPES, &raw) == NNG_ENOTSUP);
	CHECK(raw == &empty);
	CHECK(nng_socket_get_ptr(sock, NMQ_OPT_MQTT_PIPE_SNAPSHOT, &raw) == NNG_EBADTYPE);
	CHECK(raw == &empty);

	unsigned char output[sizeof(empty)];
	unsigned char original[sizeof(empty)];
	memset(output, 0xa5, sizeof(output));
	memcpy(original, output, sizeof(output));
	size_t size = sizeof(output) - 1;
	CHECK(nng_socket_get(sock, NMQ_OPT_MQTT_PIPE_SNAPSHOT, output, &size) == NNG_EINVAL);
	CHECK(size == sizeof(empty));
	CHECK(memcmp(output, original, sizeof(output)) == 0);
	size = sizeof(empty);
	CHECK(nng_socket_get(sock, NMQ_OPT_MQTT_PIPE_SNAPSHOT, NULL, &size) == NNG_EINVAL);
	CHECK(size == sizeof(empty));
	CHECK(nng_socket_get(sock, NMQ_OPT_MQTT_PIPE_SNAPSHOT, output, NULL) == NNG_EINVAL);
	CHECK(memcmp(output, original, sizeof(output)) == 0);
}

static cJSON *
request(conf_http_server *http, const char *method, const char *path,
    uint16_t status)
{
	http_msg req = { 0 };
	put_http_msg(&req, NULL, method, path, NULL, NULL, 0);
	http_msg res = process_request(&req, http, http->broker_sock);
	CHECK(res.status == status);
	CHECK(res.data != NULL && res.data_len > 0);
	cJSON *json = NULL;
	if (status == 200 && strcmp(path, "/api/v4/prometheus") == 0) {
		CHECK(strcmp(res.content_type, "text/plain") == 0);
		// HTTP message data has a length but no terminating NUL.
		char *text = nng_alloc(res.data_len + 1);
		CHECK(text != NULL);
		memcpy(text, res.data, res.data_len);
		text[res.data_len] = '\0';
		CHECK(strstr(text, "nanomq_connections_count ") != NULL);
		nng_free(text, res.data_len + 1);
	} else {
		json = cJSON_ParseWithLength(res.data, res.data_len);
		CHECK(json != NULL);
	}
	destory_http_msg(&res);
	destory_http_msg(&req);
	return json;
}

static void
check_rest(conf_http_server *http, unsigned connections)
{
	cJSON *json = request(http, "GET", "/api/v4/nodes", 200);
	cJSON *node = cJSON_GetArrayItem(cJSON_GetObjectItem(json, "data"), 0);
	cJSON *count = cJSON_GetObjectItem(node, "connections");
	CHECK(cJSON_IsNumber(count) && count->valuedouble == connections);
	cJSON_Delete(json);

	json = request(http, "GET", "/api/v4/clients", 200);
	CHECK(cJSON_GetArraySize(cJSON_GetObjectItem(json, "data")) == connections);
	cJSON_Delete(json);
	json = request(http, "GET", "/api/v4/clients/username/snapshot-user", 200);
	CHECK(cJSON_GetArraySize(cJSON_GetObjectItem(json, "data")) == connections);
	cJSON_Delete(json);
	json = request(http, "GET", "/api/v4/metrics", 200);
	count = cJSON_GetObjectItem(json, "connections");
	CHECK(cJSON_IsNumber(count) && count->valuedouble == connections);
	cJSON_Delete(json);
	cJSON_Delete(request(http, "GET", "/api/v4/prometheus", 200));
}

static void
check_rest_failure(conf_http_server *http)
{
	nng_socket invalid = NNG_SOCKET_INITIALIZER;
	conf_http_server unavailable = *http;
	unavailable.broker_sock = &invalid;
	const char *paths[] = { "/api/v4/nodes", "/api/v4/clients",
		"/api/v4/clients/snapshot-first", "/api/v4/prometheus" };
	for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
		cJSON *json = request(&unavailable, "GET", paths[i], 500);
		cJSON *code = cJSON_GetObjectItem(json, "code");
		CHECK(cJSON_IsNumber(code) && code->valueint == UNKNOWN_MISTAKE);
		cJSON_Delete(json);
	}
	cJSON_Delete(request(&unavailable, "DELETE", "/api/v4/clients/snapshot-first", 500));
}

int
main(void)
{
	conf *cfg = nng_zalloc(sizeof(*cfg));
	CHECK(cfg != NULL);
	conf_init(cfg);
	cfg->http_server.auth_type = NONE_AUTH;
	nng_socket sock = { .data = cfg };
	CHECK(nng_nmq_tcp0_open(&sock) == 0);
	CHECK(nng_socket_set_ms(sock, NNG_OPT_RECVTIMEO, 1000) == 0);
	nni_sock *core;
	CHECK(nni_sock_find(&core, sock.id) == 0);
	cfg->http_server.broker_sock = &sock;
	set_global_conf(cfg);
	dbhash_init_pipe_table();
	nanomq_init_hash_seed();

	check_option_contract(sock);
	check_rest(&cfg->http_server, 0);
	check_rest_failure(&cfg->http_server);
	cJSON_Delete(request(&cfg->http_server, "DELETE", "/api/v4/clients/missing", 404));

	snapshot_test_pipe first;
	create_pipe(core, sock, &first, "snapshot-first");
	nng_mqtt_pipe_snapshot retained = snapshot(sock);
	CHECK(retained.count == 1 && retained.ids[0] == nni_pipe_id(first.pipe));
	uint32_t first_id = retained.ids[0];
	check_rest(&cfg->http_server, 1);
	cJSON *json = request(&cfg->http_server, "GET", "/api/v4/clients/snapshot-first", 200);
	CHECK(cJSON_GetArraySize(cJSON_GetObjectItem(json, "data")) == 1);
	cJSON_Delete(json);
	cJSON_Delete(request(&cfg->http_server, "DELETE", "/api/v4/clients/snapshot-first", 200));
	dispose_pipe(sock, &first);
	check_rest(&cfg->http_server, 0);
	CHECK(retained.count == 1 && retained.ids[0] == first_id);

	snapshot_test_pipe second, third;
	create_pipe(core, sock, &second, "snapshot-second");
	create_pipe(core, sock, &third, "snapshot-third");
	uint32_t second_id = nni_pipe_id(second.pipe);
	uint32_t third_id = nni_pipe_id(third.pipe);
	nng_mqtt_pipe_snapshot current = snapshot(sock);
	CHECK(current.count == 2);
	CHECK((current.ids[0] == second_id && current.ids[1] == third_id) ||
	    (current.ids[0] == third_id && current.ids[1] == second_id));
	CHECK(current.ids != retained.ids);
	CHECK(retained.ids[0] == first_id);
	check_rest(&cfg->http_server, 2);
	dispose_pipe(sock, &second);
	CHECK(current.count == 2);
	CHECK((current.ids[0] == second_id && current.ids[1] == third_id) ||
	    (current.ids[0] == third_id && current.ids[1] == second_id));
	nng_mqtt_pipe_snapshot_free(&current);
	current = snapshot(sock);
	CHECK(current.count == 1 && current.ids[0] == third_id);
	nng_mqtt_pipe_snapshot_free(&current);
	dispose_pipe(sock, &third);
	current = snapshot(sock);
	CHECK(current.count == 0 && current.ids == NULL);
	nng_mqtt_pipe_snapshot_free(&current);

	set_global_conf(NULL);
	nni_sock_rele(core);
	CHECK(nng_close(sock) == 0);
	nni_reap_drain();
	// The snapshot remains caller-owned even after the owning socket is gone.
	CHECK(retained.count == 1 && retained.ids[0] == first_id);
	nng_mqtt_pipe_snapshot_free(&retained);
	CHECK(retained.count == 0 && retained.ids == NULL);
	nng_mqtt_pipe_snapshot_free(&retained);
	dbhash_destroy_pipe_table();
	nng_fini();
	puts("Snapshot API and REST contract checks passed");
	return 0;
}
