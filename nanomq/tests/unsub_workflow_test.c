//
// Copyright 2026 NanoMQ Team, Inc. <jaylin@emqx.io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt). A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

// Run valid requests through the real worker, decoder, subscription stores,
// bridge handler and ACK encoder. Only asynchronous I/O is intercepted.
#include "include/bridge.h"
#include "include/sub_handler.h"
#include "nng/protocol/mqtt/mqtt_parser.h"
#include "nng/supplemental/nanolib/hash_table.h"
#include "nng/supplemental/nanolib/mqtt_db.h"

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

extern void server_cb(void *);

static const char *filters[] = {
	"workflow/plain", "workflow/missing", "workflow/plain",
	"wild/+/value", "$share/workers/shared/#", "$SYS/workflow"
};
#define FILTER_COUNT (sizeof(filters) / sizeof(filters[0]))

static nng_mqtt_client bridge_client_fixture;
static size_t bridge_calls;
static int send_calls, recv_calls, finish_calls;

int
__wrap_nng_mqtt_unsubscribe_async(nng_mqtt_client *client,
    nng_mqtt_topic *topics, size_t count, property *props)
{
	CHECK(client == &bridge_client_fixture);
	CHECK(count == 1 && props == NULL);
	CHECK(bridge_calls < FILTER_COUNT);
	CHECK(topics[0].length == strlen(filters[bridge_calls]));
	CHECK(memcmp(topics[0].buf, filters[bridge_calls], topics[0].length) == 0);
	bridge_calls++;
	return 0;
}

void
__wrap_nng_ctx_send(nng_ctx ctx, nng_aio *aio)
{
	(void) ctx;
	CHECK(nng_aio_get_msg(aio) != NULL);
	send_calls++;
}

void
__wrap_nng_ctx_recv(nng_ctx ctx, nng_aio *aio)
{
	(void) ctx;
	CHECK(nng_aio_get_msg(aio) == NULL);
	recv_calls++;
}

void
__wrap_nng_aio_finish(nng_aio *aio, int result)
{
	(void) aio;
	CHECK(result == 0);
	finish_calls++;
}

static nng_msg *
valid_request(uint8_t version, bool user_property, uint16_t packet_id)
{
	nng_msg *msg;
	CHECK(nng_msg_alloc(&msg, 0) == 0);
	nng_msg_set_cmd_type(msg, CMD_UNSUBSCRIBE);
	CHECK(nng_msg_append_u16(msg, packet_id) == 0);
	if (version == MQTT_PROTOCOL_VERSION_v5) {
		// One User Property, "key" = "val", or an empty property block.
		const uint8_t props[] = {
			11, 0x26, 0, 3, 'k', 'e', 'y', 0, 3, 'v', 'a', 'l'
		};
		const uint8_t empty = 0;
		CHECK(nng_msg_append(msg, user_property ? props : &empty,
		    user_property ? sizeof(props) : 1) == 0);
	}
	for (size_t i = 0; i < FILTER_COUNT; i++) {
		CHECK(nng_msg_append_u16(msg, strlen(filters[i])) == 0);
		CHECK(nng_msg_append(msg, filters[i], strlen(filters[i])) == 0);
	}
	const uint8_t command = CMD_UNSUBSCRIBE | 0x02;
	uint8_t remaining[4];
	size_t len = put_var_integer(remaining, nng_msg_len(msg));
	CHECK(nng_msg_header_append(msg, &command, 1) == 0);
	CHECK(nng_msg_header_append(msg, remaining, len) == 0);
	return msg;
}

static void
subscribe_filter(nano_work *work, uint32_t pipe_id, const char *filter)
{
	topic_node topic = { 0 };
	topic.topic.body = (char *) filter;
	topic.topic.len = strlen(filter);
	topic.retain_handling = 2;
	packet_subscribe packet = { .packet_id = 1, .node = &topic };
	work->sub_pkt = &packet;
	work->pid.id = pipe_id;
	CHECK(sub_ctx_handle(work) == 0);
	work->sub_pkt = NULL;
}

static void
check_match(dbtree *db, const char *topic, bool shared, uint32_t pipe_id,
    bool expected)
{
	uint32_t *clients = shared
	    ? dbtree_find_shared_clients(db, (char *) topic)
	    : dbtree_find_clients(db, (char *) topic);
	bool found = false;
	for (size_t i = 0; i < cvector_size(clients); i++) {
		if (clients[i] == pipe_id) {
			found = true;
		}
	}
	cvector_free(clients);
	CHECK(found == expected);
}

static void
check_workflow(uint8_t version, bool mounted, bool user_property,
    bool transparent)
{
	const uint32_t owner = 17, other = 18;
	const uint16_t packet_id = 0x3456;
	const char *plain = mounted ? "tenant/workflow/plain" : "workflow/plain";
	const char *wild = mounted ? "tenant/wild/+/value" : "wild/+/value";
	const char *wild_topic = mounted ? "tenant/wild/one/value" : "wild/one/value";
	const char *shared = mounted ? "$share/workers/tenant/shared/#"
	                             : "$share/workers/shared/#";
	const char *shared_topic = mounted ? "tenant/shared/one" : "shared/one";
	const char *keep = mounted ? "tenant/keep/only" : "keep/only";
	conf config = { 0 };
	conf_bridge_node node = { .enable = true, .transparent = transparent };
	conf_bridge_node *nodes[] = { &node };
	bridge_param param = { .client = &bridge_client_fixture };
	node.bridge_arg = &param;
	CHECK(nng_mtx_alloc(&node.mtx) == 0);
	config.bridge.count = 1;
	config.bridge.nodes = nodes;
	struct pipe_content pipe_content = { 0 };
	nano_work work = { 0 };
	work.config = &config;
	work.pipe_ct = &pipe_content;
	work.proto = PROTO_MQTT_BROKER;
	work.proto_ver = version;
	dbtree_create(&work.db);
	dbtree_create(&work.db_ret);
	CHECK(work.db != NULL && work.db_ret != NULL);
	conn_param *cp;
	CHECK(conn_param_alloc(&cp) == 0);
	conn_param_set_clientid(cp, "unsub-workflow");
	conn_param_set_proto_ver(cp, version);
	if (mounted) {
		conn_param_set_mount_point(cp, "tenant");
	}
	work.cparam = cp;
	subscribe_filter(&work, owner, filters[0]);
	subscribe_filter(&work, owner, filters[3]);
	subscribe_filter(&work, owner, filters[4]);
	subscribe_filter(&work, owner, filters[5]);
	subscribe_filter(&work, owner, "keep/only");
	subscribe_filter(&work, other, filters[0]);
	CHECK(dbhash_check_topic(owner, (char *) plain));
	CHECK(dbhash_check_topic(owner, (char *) wild));
	CHECK(dbhash_check_topic(owner, (char *) shared));
	CHECK(dbhash_check_topic(owner, "$SYS/workflow"));
	check_match(work.db, plain, false, owner, true);
	check_match(work.db, wild_topic, false, owner, true);
	check_match(work.db, shared_topic, true, owner, true);
	check_match(work.db, "$SYS/workflow", false, owner, true);

	nng_msg *msg = valid_request(version, user_property, packet_id);
	conn_param_clone(cp); // The protocol's reference is released in SEND.
	nng_msg_set_conn_param(msg, cp);
	nng_msg_set_pipe(msg, (nng_pipe) { .id = owner });
	CHECK(nng_aio_alloc(&work.aio, NULL, NULL) == 0);
	nng_aio_set_msg(work.aio, msg);
	work.state = RECV;
	bridge_calls = 0;
	send_calls = recv_calls = finish_calls = 0;
	server_cb(&work);
	CHECK(work.state == SEND && work.code == NNG_MQTT_SUCCESS);
	CHECK(work.unsub_pkt == NULL && work.msg == NULL);
	CHECK(nng_aio_get_msg(work.aio) == msg);
	CHECK(send_calls == 1 && finish_calls == 1 && recv_calls == 0);
	CHECK(bridge_calls == (transparent ? FILTER_COUNT : 0));
	CHECK(conn_param_ref(cp) == 2);

	// Preserve the existing success reason for absent and repeated filters:
	// sub_ctx_del is idempotent and returns success for both.
	const uint8_t ack3[] = { 0x34, 0x56 };
	const uint8_t ack5[] = { 0x34, 0x56, 0, 0, 0, 0, 0, 0, 0 };
	const uint8_t *body = version == MQTT_PROTOCOL_VERSION_v5 ? ack5 : ack3;
	size_t body_len = version == MQTT_PROTOCOL_VERSION_v5 ? sizeof(ack5) : sizeof(ack3);
	const uint8_t header[] = { CMD_UNSUBACK, body_len };
	CHECK(nng_msg_header_len(msg) == sizeof(header));
	CHECK(memcmp(nng_msg_header(msg), header, sizeof(header)) == 0);
	CHECK(nng_msg_len(msg) == body_len);
	CHECK(memcmp(nng_msg_body(msg), body, body_len) == 0);
	CHECK(!dbhash_check_topic(owner, (char *) plain));
	CHECK(!dbhash_check_topic(owner, (char *) wild));
	CHECK(!dbhash_check_topic(owner, (char *) shared));
	CHECK(!dbhash_check_topic(owner, "$SYS/workflow"));
	CHECK(dbhash_check_topic(owner, (char *) keep));
	CHECK(dbhash_check_topic(other, (char *) plain));
	check_match(work.db, plain, false, owner, false);
	check_match(work.db, plain, false, other, true);
	check_match(work.db, wild_topic, false, owner, false);
	check_match(work.db, shared_topic, true, owner, false);
	check_match(work.db, "$SYS/workflow", false, owner, false);
	check_match(work.db, keep, false, owner, true);

	// Complete the successful send, then run the real SEND -> RECV cleanup.
	nng_aio_set_msg(work.aio, NULL);
	nng_msg_free(msg);
	server_cb(&work);
	CHECK(work.state == RECV && work.flag == 0);
	CHECK(recv_calls == 1 && send_calls == 1 && finish_calls == 1);
	CHECK(conn_param_ref(cp) == 1);
	CHECK(sub_ctx_del(work.db, (char *) keep, owner) == 0);
	CHECK(sub_ctx_del(work.db, (char *) plain, other) == 0);
	nng_aio_free(work.aio);
	conn_param_free(cp);
	dbtree_destory(work.db);
	dbtree_destory(work.db_ret);
	nng_mtx_free(node.mtx);
}

int
main(void)
{
	dbhash_init_pipe_table();
	check_workflow(MQTT_PROTOCOL_VERSION_v311, false, false, false);
	check_workflow(MQTT_PROTOCOL_VERSION_v5, false, false, true);
	check_workflow(MQTT_PROTOCOL_VERSION_v5, true, true, true);
	dbhash_destroy_pipe_table();
	nng_fini();
	return 0;
}
