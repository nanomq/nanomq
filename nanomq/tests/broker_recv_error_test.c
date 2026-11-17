// Verify receive errors and event completion through the real broker callback.
#include "include/broker.h"
#include "include/pub_handler.h"
#include "nng/protocol/mqtt/mqtt_parser.h"
#include "nng/supplemental/nanolib/hash_table.h"

#include <stdio.h>
#include <stdlib.h>

extern void server_cb(void *);

#define CHECK(expr) do { if (!(expr)) { \
	fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expr); \
	abort(); \
} } while (0)

static unsigned receives;
static uint32_t received_ctx;

void
__wrap_nng_ctx_recv(nng_ctx ctx, nng_aio *aio)
{
	(void) aio;
	received_ctx = ctx.id;
	receives++;
}

static void
check_event_completion(bool bridge, bool disconnect)
{
	conf cfg = { 0 };
	struct pipe_content pipes = { 0 };
	nano_work work = { .proto = bridge ? PROTO_MQTT_BRIDGE : PROTO_MQTT_BROKER,
	    .state = RECV, .config = &cfg, .pipe_ct = &pipes,
	    .ctx = { .id = 1 }, .extra_ctx = { .id = 2 } };
	conn_param *cp;
	CHECK(conn_param_alloc(&cp) == 0);
	// Decode a clean-session CONNECT without a will, as the transport does.
	uint8_t connect[] = "\x10\x1b\x00\x04MQTT\x04\x02\x00\x1e\x00\x0f"
	                    "disconnect-test";
	CHECK(conn_handler(connect, cp, sizeof(connect) - 1) == 0);
	dbtree_create(&work.db);
	dbtree_create(&work.db_ret);
	CHECK(nng_aio_alloc(&work.aio, NULL, NULL) == 0);

	// Match the bridge client's notification: a retained wire PUBLISH,
	// CMD_DISCONNECT_EV metadata, and NNG_ECONNSHUT as the receive result.
	nng_msg *msg = disconnect
	    ? nano_msg_notify(cp, SERVER_SHUTTING_DOWN, bridge, false)
	    : nano_encode_publish_msg(MQTT_PROTOCOL_VERSION_v311, 0, false,
	          false, (const uint8_t *) "order", 5, NULL, "order-test", NULL);
	CHECK(msg != NULL && nng_msg_get_type(msg) == CMD_PUBLISH);
	nng_msg_set_cmd_type(msg, disconnect ? CMD_DISCONNECT_EV : CMD_PUBLISH);
	nng_msg_set_conn_param(msg, cp);
	conn_param_clone(cp); // the application owns a message reference
	if (disconnect && !bridge) {
		conn_param_clone(cp); // the broker notification also transfers this ref
	}
	nng_aio_set_msg(work.aio, msg);
	nng_aio_finish(work.aio, bridge ? NNG_ECONNSHUT : 0);
	nng_aio_wait(work.aio);
	receives = 0;
	server_cb(&work);
	if (disconnect) {
		// Before the fix, bridge delivery fatals in WAIT on ECONNSHUT.
		// Both bridge and local disconnect events use completed-AIO WAIT.
		nng_aio_wait(work.aio);
		CHECK(work.state == WAIT && nng_aio_result(work.aio) == 0);
		CHECK(receives == 0 && work.msg == msg && work.pub_packet != NULL);
		CHECK(work.pub_packet->fixed_header.retain == bridge);
		server_cb(&work);
	}
	// A normal PUBLISH must still fan out inline without another dispatch.
	CHECK(work.state == RECV && receives == 1);
	CHECK(received_ctx == (bridge ? work.extra_ctx.id : work.ctx.id));
	CHECK(work.msg == NULL && work.pub_packet == NULL && pipes.msg_infos == NULL);
	char topic[] = CLIENT_STATUS_TOPIC "/disconnect-test";
	nng_msg *retained = dbtree_delete_retain(work.db_ret, topic);
	CHECK((retained != NULL) == bridge);
	if (retained != NULL) {
		nng_msg_free(retained);
	}
	CHECK(conn_param_ref(cp) == 1);
	conn_param_free(cp);
	nng_aio_free(work.aio);
	dbtree_destory(work.db);
	dbtree_destory(work.db_ret);
}

int
main(void)
{
	nano_work work = { .proto = PROTO_MQTT_BROKER };
	CHECK(nng_aio_alloc(&work.aio, NULL, NULL) == 0);
	int errors[] = { NNG_ECLOSED, NNG_ECANCELED, NNG_ESTATE, NNG_ETIMEDOUT };
	for (unsigned i = 0; i < sizeof(errors) / sizeof(errors[0]); i++) {
		work.state = RECV;
		receives = 0;
		nng_aio_finish(work.aio, errors[i]);
		nng_aio_wait(work.aio);
		server_cb(&work);
		CHECK(receives == (errors[i] == NNG_ETIMEDOUT ? 1u : 0u));
	}
	nng_aio_free(work.aio);
	dbhash_init_pipe_table();
	dbhash_init_alias_table();
	check_event_completion(true, true);
	check_event_completion(false, true);
	check_event_completion(false, false);
	dbhash_destroy_alias_table();
	dbhash_destroy_pipe_table();
	nng_fini();
	puts("PASS receive errors, disconnect event completion and inline PUBLISH");
	return 0;
}
