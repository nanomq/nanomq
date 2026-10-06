//
// Copyright 2026 NanoMQ Team, Inc. <jaylin@emqx.io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//
// Unit tests for NNG sub0 -> MQTT conversion (nng_sub0_msg_adapter).
//
// Verifies exact-topic matching semantics: for every delimiter value, the
// message topic must be identical to remote_topic (delimiter must
// immediately follow remote_topic), otherwise the message is rejected.
//
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "nng/nng.h"
#include "nng/mqtt/mqtt_client.h"
#include "nng/protocol/mqtt/mqtt_parser.h"
#include "nng/supplemental/nanolib/conf.h"

// Build a sub rule (topics) with optional delimiter and local_topic.
// remote/delim/local must be string literals (not freed).
static topics *
mk_rule(const char *remote, const char *delim, const char *local)
{
	topics *t = nng_alloc(sizeof(topics));
	assert(t != NULL);
	memset(t, 0, sizeof(topics));
	t->remote_topic = (char *) remote;
	t->remote_topic_len = (uint32_t) strlen(remote);
	if (delim != NULL) {
		t->nng_delimiter = (char *) delim;
		t->nng_delimiter_len = (uint32_t) strlen(delim);
	}
	if (local != NULL) {
		t->local_topic = (char *) local;
		t->local_topic_len = (uint32_t) strlen(local);
	}
	return t;
}

static conf_nng_sub_node *
mk_node(topics **rules, size_t n)
{
	conf_nng_sub_node *node = nng_alloc(sizeof(conf_nng_sub_node));
	assert(node != NULL);
	memset(node, 0, sizeof(conf_nng_sub_node));
	node->sub_list = rules;
	node->inwards_count = n;
	return node;
}

static nng_msg *
mk_msg(const char *body)
{
	nng_msg *m = NULL;
	assert(nng_msg_alloc(&m, 0) == 0);
	if (strlen(body) > 0) {
		assert(nng_msg_append(m, body, strlen(body)) == 0);
	}
	return m;
}

// Replace rules[i] with a new rule, freeing the previous one if any.
static void
set_rule(topics **slot, const char *remote, const char *delim,
    const char *local)
{
	if (*slot != NULL) {
		nng_free(*slot, sizeof(topics));
	}
	*slot = mk_rule(remote, delim, local);
}

// Verify the MQTT message produced by the adapter: topic, payload, qos.
static void
check_publish(nng_msg *m, const char *topic, const char *payload,
    size_t payload_len)
{
	assert(m != NULL);

	uint32_t    tlen = 0;
	const char *t    = nng_mqtt_msg_get_publish_topic(m, &tlen);
	assert(t != NULL);
	assert(tlen == strlen(topic));
	assert(memcmp(t, topic, tlen) == 0);

	uint32_t plen = 0;
	uint8_t *p    = nng_mqtt_msg_get_publish_payload(m, &plen);
	assert(plen == payload_len);
	if (payload_len > 0) {
		assert(p != NULL);
		assert(memcmp(p, payload, plen) == 0);
	}

	assert(nng_mqtt_msg_get_publish_qos(m) == 0);
}

int
main(void)
{
	nng_msg *origin, *mqtt_msg;
	topics *rules[2] = { NULL, NULL };

	// --- 1. ":" delimiter, exact topic match -> forwarded ---
	conf_nng_sub_node *node = mk_node(rules, 1);
	set_rule(&rules[0], "topic_can", ":", "topic_can");
	origin = mk_msg("topic_can:hello");
	mqtt_msg = nng_sub0_msg_adapter(origin, node);
	check_publish(mqtt_msg, "topic_can", "hello", 5);
	nng_msg_free(mqtt_msg);
	nng_msg_free(origin);

	// --- 2. ":" delimiter, topic extends beyond remote_topic -> dropped ---
	//     regression: "topic_can1234:hello" must NOT be forwarded
	origin = mk_msg("topic_can1234:hello");
	mqtt_msg = nng_sub0_msg_adapter(origin, node);
	assert(mqtt_msg == NULL);
	nng_msg_free(origin);

	// --- 3. bare topic (no delimiter, no payload) -> dropped
	//     (no payload means no delimiter follows the topic; rejected
	//     at extract time by the body-too-short check) ---
	origin = mk_msg("topic_can");
	mqtt_msg = nng_sub0_msg_adapter(origin, node);
	assert(mqtt_msg == NULL);
	nng_msg_free(origin);

	// --- 4. delimiter inside payload -> payload keeps the rest ---
	origin = mk_msg("topic_can:sub:hello");
	mqtt_msg = nng_sub0_msg_adapter(origin, node);
	check_publish(mqtt_msg, "topic_can", "sub:hello", 9);
	nng_msg_free(mqtt_msg);
	nng_msg_free(origin);

	// --- 5. default "/" delimiter, exact match -> forwarded ---
	set_rule(&rules[0], "nng/pub", NULL, "mqtt/pub");
	origin = mk_msg("nng/pub/123/hello");
	mqtt_msg = nng_sub0_msg_adapter(origin, node);
	check_publish(mqtt_msg, "mqtt/pub", "123/hello", 9);
	nng_msg_free(mqtt_msg);
	nng_msg_free(origin);

	// --- 6. "/" delimiter, extended topic -> dropped ---
	origin = mk_msg("nng/pubX/1");
	mqtt_msg = nng_sub0_msg_adapter(origin, node);
	assert(mqtt_msg == NULL);
	nng_msg_free(origin);

	// --- 7. multi-char delimiter ":::", exact match -> forwarded ---
	set_rule(&rules[0], "diff_len_sub", ":::", "diff_len_pub");
	origin = mk_msg("diff_len_sub:::hello");
	mqtt_msg = nng_sub0_msg_adapter(origin, node);
	check_publish(mqtt_msg, "diff_len_pub", "hello", 5);
	nng_msg_free(mqtt_msg);
	nng_msg_free(origin);

	// --- 8. multi-char delimiter, extended topic -> dropped ---
	origin = mk_msg("diff_len_subxx:::hello");
	mqtt_msg = nng_sub0_msg_adapter(origin, node);
	assert(mqtt_msg == NULL);
	nng_msg_free(origin);

	// --- 9. remote_topic carries trailing delimiter -> topic trimmed,
	//         dest falls back to dynamic topic from body ---
	set_rule(&rules[0], "topic_can:", ":", NULL);
	origin = mk_msg("topic_can:hello");
	mqtt_msg = nng_sub0_msg_adapter(origin, node);
	check_publish(mqtt_msg, "topic_can", "hello", 5);
	nng_msg_free(mqtt_msg);
	nng_msg_free(origin);

	// --- 10. no local_topic, exact match -> dest = remote_topic ---
	set_rule(&rules[0], "result", ":", NULL);
	origin = mk_msg("result:ok");
	mqtt_msg = nng_sub0_msg_adapter(origin, node);
	check_publish(mqtt_msg, "result", "ok", 2);
	nng_msg_free(mqtt_msg);
	nng_msg_free(origin);

	// --- 11. first rule rejects (extended topic), second rule matches ---
	set_rule(&rules[0], "topic_can", ":", "mqtt/topic_can");
	set_rule(&rules[1], "topic_can1234", ":", "mqtt/topic_can1234");
	node->inwards_count = 2;
	origin = mk_msg("topic_can1234:hello");
	mqtt_msg = nng_sub0_msg_adapter(origin, node);
	check_publish(mqtt_msg, "mqtt/topic_can1234", "hello", 5);
	nng_msg_free(mqtt_msg);
	nng_msg_free(origin);

	// --- 12. empty body -> dropped ---
	set_rule(&rules[0], "topic_can", ":", "topic_can");
	node->inwards_count = 1;
	origin = mk_msg("");
	mqtt_msg = nng_sub0_msg_adapter(origin, node);
	assert(mqtt_msg == NULL);
	nng_msg_free(origin);

	nng_free(node, sizeof(conf_nng_sub_node));
	for (size_t i = 0; i < 2; i++) {
		if (rules[i] != NULL)
			nng_free(rules[i], sizeof(topics));
	}

	printf("All nng bridge adapter tests passed.\n");
	return 0;
}
