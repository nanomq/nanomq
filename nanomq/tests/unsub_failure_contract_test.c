//
// Copyright 2026 NanoMQ Team, Inc. <jaylin@emqx.io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

// Exercise failure ownership with linker fault injection and valid local
// messages. No listener or malformed wire packet is needed.
#include "include/bridge.h"
#include "include/unsub_handler.h"
#include "nng/protocol/mqtt/mqtt_parser.h"

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
extern int __real_decode_unsub_msg(nano_work *);
extern int __real_encode_unsuback_msg(nng_msg *, nano_work *);
extern property *__real_decode_properties(nng_msg *, uint32_t *, uint32_t *, bool);
extern int __real_property_free(property *);
extern void *__real_nng_zalloc(size_t);
extern void __real_nng_free(void *, size_t);

static int decode_error, context_error, ack_error;
static int decode_calls, context_calls, bridge_calls, ack_calls;
static int finish_calls, send_calls;
static int fail_alloc_after = -1;
static int fail_node_after = -1;
static bool fail_properties, track_allocations;
static void *allocations[8];
static property *watched_properties;

static void
watch_allocation(void *ptr)
{
	CHECK(ptr != NULL);
	for (size_t i = 0; i < sizeof(allocations) / sizeof(*allocations); i++) {
		if (allocations[i] == NULL) {
			allocations[i] = ptr;
			return;
		}
	}
	CHECK(false);
}

static void
check_released(void)
{
	for (size_t i = 0; i < sizeof(allocations) / sizeof(*allocations); i++) {
		CHECK(allocations[i] == NULL);
	}
	CHECK(watched_properties == NULL);
}

void *
__wrap_nng_zalloc(size_t size)
{
	if (fail_alloc_after >= 0 && fail_alloc_after-- == 0) {
		return NULL;
	}
	void *ptr = __real_nng_zalloc(size);
	if (track_allocations) {
		watch_allocation(ptr);
	}
	return ptr;
}

void
__wrap_nng_free(void *ptr, size_t size)
{
	for (size_t i = 0; i < sizeof(allocations) / sizeof(*allocations); i++) {
		if (allocations[i] == ptr) {
			allocations[i] = NULL;
		}
	}
	__real_nng_free(ptr, size);
}

int
__wrap_property_free(property *prop)
{
	if (prop == watched_properties) {
		watched_properties = NULL;
	}
	return __real_property_free(prop);
}

property *
__wrap_decode_properties(nng_msg *msg, uint32_t *pos, uint32_t *len,
    bool copy_value)
{
	if (fail_properties) {
		*len = UINT32_MAX;
		return NULL;
	}
	return __real_decode_properties(msg, pos, len, copy_value);
}

int
__wrap_decode_unsub_msg(nano_work *work)
{
	decode_calls++;
	CHECK(work->unsub_pkt != NULL);
	CHECK(work->unsub_pkt->node == NULL);
	CHECK(work->unsub_pkt->properties == NULL);
	if (decode_error != 0) {
		return decode_error;
	}
	fail_alloc_after = fail_node_after;
	return __real_decode_unsub_msg(work);
}

int
__wrap_unsub_ctx_handle(nano_work *work)
{
	context_calls++;
	CHECK(work->unsub_pkt->node != NULL);
	return context_error;
}

bool
__wrap_bridge_sub_handler(nano_work *work)
{
	bridge_calls++;
	CHECK(work->unsub_pkt->node != NULL);
	return true;
}

int
__wrap_encode_unsuback_msg(nng_msg *msg, nano_work *work)
{
	ack_calls++;
	if (ack_error != 0) {
		return ack_error;
	}
	return __real_encode_unsuback_msg(msg, work);
}

void
__wrap_nng_aio_finish(nng_aio *aio, int result)
{
	(void) aio;
	CHECK(result == 0);
	finish_calls++;
}

void
__wrap_nng_ctx_send(nng_ctx ctx, nng_aio *aio)
{
	(void) ctx;
	CHECK(nng_aio_get_msg(aio) != NULL);
	send_calls++;
}

static nng_msg *
valid_unsubscribe(uint8_t version)
{
	nng_msg *msg;
	const char *topics[] = { "contract/first", "contract/second" };
	CHECK(nng_msg_alloc(&msg, 0) == 0);
	nng_msg_set_cmd_type(msg, CMD_UNSUBSCRIBE);
	CHECK(nng_msg_append_u16(msg, 7) == 0);
	if (version == MQTT_PROTOCOL_VERSION_v5) {
		const uint8_t no_properties = 0;
		CHECK(nng_msg_append(msg, &no_properties, 1) == 0);
	}
	for (size_t i = 0; i < sizeof(topics) / sizeof(*topics); i++) {
		CHECK(nng_msg_append_u16(msg, strlen(topics[i])) == 0);
		CHECK(nng_msg_append(msg, topics[i], strlen(topics[i])) == 0);
	}
	const uint8_t command = CMD_UNSUBSCRIBE | 0x02;
	uint8_t remaining[4];
	size_t size = put_var_integer(remaining, nng_msg_len(msg));
	CHECK(nng_msg_header_append(msg, &command, 1) == 0);
	CHECK(nng_msg_header_append(msg, remaining, size) == 0);
	return msg;
}

static void
check_decoder(uint8_t version, bool property_error, int node_oom)
{
	nano_work work = { 0 };
	work.proto_ver = version;
	work.msg = valid_unsubscribe(version);
	work.unsub_pkt = nng_alloc(sizeof(*work.unsub_pkt));
	CHECK(work.unsub_pkt != NULL);
	// The decoder must initialize even a caller's nonzeroing allocation.
	memset(work.unsub_pkt, 0xa5, sizeof(*work.unsub_pkt));
	watch_allocation(work.unsub_pkt);
	track_allocations = true;
	fail_properties = property_error;
	fail_alloc_after = node_oom;
	int rv = __real_decode_unsub_msg(&work);
	fail_alloc_after = -1;
	fail_properties = false;
	track_allocations = false;
	if (property_error || node_oom == 0) {
		CHECK(rv == (property_error ? PROTOCOL_ERROR : NNG_ENOMEM));
		CHECK(work.unsub_pkt->node == NULL);
	} else {
		if (rv != (node_oom > 0 ? NNG_ENOMEM : 0)) {
			fprintf(stderr, "decode v%u, allocation failure %d: %d\n",
			    version, node_oom, rv);
		}
		CHECK(rv == (node_oom > 0 ? NNG_ENOMEM : 0));
		topic_node *node = work.unsub_pkt->node;
		CHECK(node != NULL && node->topic.len == strlen("contract/first"));
		CHECK(memcmp(node->topic.body, "contract/first", node->topic.len) == 0);
		CHECK((node->next == NULL) == (node_oom > 0));
		if (node->next != NULL) {
			CHECK(node->next->next == NULL);
			CHECK(node->next->topic.len == strlen("contract/second"));
		}
	}
	unsub_pkt_free(work.unsub_pkt);
	check_released();
	nng_msg_free(work.msg);
}

static void
check_empty_cleanup(void)
{
	unsub_pkt_free(NULL);
	packet_unsubscribe *pkt = nng_zalloc(sizeof(*pkt));
	CHECK(pkt != NULL);
	watch_allocation(pkt);
	pkt->properties = property_alloc();
	CHECK(pkt->properties != NULL);
	watched_properties = pkt->properties;
	unsub_pkt_free(pkt);
	check_released();
}

static void
check_worker(int decode_rv, int context_rv, int ack_rv, int alloc_oom,
    int node_oom, int expected_code)
{
	nano_work work = { 0 };
	conn_param *cp;
	CHECK(conn_param_alloc(&cp) == 0);
	conn_param_set_proto_ver(cp, MQTT_PROTOCOL_VERSION_v5);
	// Retain a test reference so the worker's one release can be verified.
	conn_param_clone(cp);
	nng_msg *msg = valid_unsubscribe(MQTT_PROTOCOL_VERSION_v5);
	nng_msg_set_conn_param(msg, cp);
	CHECK(nng_aio_alloc(&work.aio, NULL, NULL) == 0);
	nng_aio_set_msg(work.aio, msg);
	work.state = RECV;
	work.proto = PROTO_MQTT_BROKER;
	decode_error = decode_rv;
	context_error = context_rv;
	ack_error = ack_rv;
	decode_calls = context_calls = bridge_calls = ack_calls = 0;
	finish_calls = send_calls = 0;
	fail_alloc_after = alloc_oom;
	fail_node_after = node_oom;
	track_allocations = true;
	server_cb(&work);
	track_allocations = false;
	fail_alloc_after = fail_node_after = -1;
	CHECK(finish_calls == 1);
	CHECK(decode_calls == (alloc_oom < 0));
	CHECK(context_calls == (alloc_oom < 0 && decode_rv == 0 && node_oom < 0));
	int applied = context_calls != 0 && context_rv == 0;
	CHECK(bridge_calls == applied && ack_calls == applied);
	CHECK(work.unsub_pkt == NULL);
	check_released();
	if (expected_code != NNG_MQTT_SUCCESS) {
		CHECK(work.state == CLOSE && work.code == expected_code);
		CHECK(work.cparam == NULL && nng_msg_get_conn_param(msg) == NULL);
		CHECK(work.msg == msg && nng_aio_get_msg(work.aio) == NULL);
		CHECK(conn_param_ref(cp) == 1 && send_calls == 0);
	} else {
		CHECK(work.state == SEND && send_calls == 1);
		CHECK(work.msg == NULL && nng_aio_get_msg(work.aio) == msg);
		CHECK(work.cparam == cp && conn_param_ref(cp) == 2);
		CHECK(*(uint8_t *) nng_msg_header(msg) == CMD_UNSUBACK);
		// Simulate the SEND state's release after inspecting its ownership.
		nng_msg_set_conn_param(msg, NULL);
		conn_param_free(work.cparam);
	}
	nng_aio_set_msg(work.aio, NULL);
	nng_msg_free(msg);
	nng_aio_free(work.aio);
	conn_param_free(cp);
}

int
main(void)
{
	check_empty_cleanup();
	check_decoder(MQTT_PROTOCOL_VERSION_v311, false, -1);
	check_decoder(MQTT_PROTOCOL_VERSION_v5, false, -1);
	check_decoder(MQTT_PROTOCOL_VERSION_v5, true, -1);
	check_decoder(MQTT_PROTOCOL_VERSION_v5, false, 0);
	check_decoder(MQTT_PROTOCOL_VERSION_v5, false, 1);
	check_worker(PROTOCOL_ERROR, 0, 0, -1, -1, PROTOCOL_ERROR);
	check_worker(0, 0, 0, 0, -1, UNSPECIFIED_ERROR);
	check_worker(0, 0, 0, -1, 1, UNSPECIFIED_ERROR);
	check_worker(0, PROTOCOL_ERROR, 0, -1, -1, PROTOCOL_ERROR);
	check_worker(0, 0, NNG_ENOMEM, -1, -1, UNSPECIFIED_ERROR);
	check_worker(0, 0, 0, -1, -1, NNG_MQTT_SUCCESS);
	nng_fini();
	return 0;
}
