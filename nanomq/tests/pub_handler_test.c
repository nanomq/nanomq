#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "include/nanomq.h"
#include "include/pub_handler.h"
#include "nng/supplemental/nanolib/conf.h"
#include "nng/supplemental/nanolib/hash_table.h"
#include "nng/protocol/mqtt/mqtt_parser.h" // conn_param_alloc/free

// Build a MQTT v5 PUBLISH message carrying an optional topic and a
// TOPIC_ALIAS property: [topic][props: 0x23 alias u16][payload]
static void
build_v5_pub_msg(nng_msg **msgp, const char *topic, uint16_t alias,
    const char *payload)
{
	uint32_t topic_len = strlen(topic);
	uint32_t pay_len   = strlen(payload);
	uint32_t prop_len  = 3; // TOPIC_ALIAS id (1) + alias value (2)
	uint32_t remain    = 2 + topic_len + 1 + prop_len + pay_len;

	nng_msg *msg;
	nng_msg_alloc(&msg, 0);

	uint8_t topic_buf[2];
	NNI_PUT16(topic_buf, (uint16_t) topic_len);
	nng_msg_append(msg, topic_buf, 2);
	if (topic_len > 0) {
		nng_msg_append(msg, topic, topic_len);
	}
	uint8_t prop_buf[4] = { (uint8_t) prop_len, 0x23, 0x00, 0x00 };
	NNI_PUT16(prop_buf + 2, alias);
	nng_msg_append(msg, prop_buf, prop_len + 1);
	nng_msg_append(msg, payload, pay_len);

	uint8_t fix_header[2] = { 0x30, (uint8_t) remain };
	nng_msg_header_append(msg, fix_header, 2);

	*msgp = msg;
}

static void
init_v5_pub_work(nano_work *work, conf *cfg, uint32_t pid, nng_msg *msg)
{
	work->config    = cfg;
	work->proto     = PROTO_MQTT_BROKER;
	work->proto_ver = MQTT_PROTOCOL_VERSION_v5;
	work->pipe_ct   = nng_zalloc(sizeof(struct pipe_content));
	work->pid.id    = pid;
	conn_param_alloc(&work->cparam);
	work->msg       = msg;
	// the transport attaches the conn_param to each incoming message;
	// check_properties() requires it when a TOPIC_ALIAS property is
	// present in a v5 PUBLISH
	nng_msg_set_conn_param(msg, work->cparam);
	dbtree_create(&work->db);
}

static void
release_v5_pub_work(nano_work *work)
{
	free_pub_packet(work->pub_packet);
	nng_msg_free(work->msg);
	conn_param_free(work->cparam);
	nng_free(work->pipe_ct, sizeof(struct pipe_content));
	dbtree_destory(work->db);
	nng_free(work, sizeof(*work));
}

void
test_handler_pub()
{
	reason_code rc = 0;
	// init work
	nano_work *work;
	work            = nng_zalloc(sizeof(*work));
	work->config    = NULL;
	work->pipe_ct   = nng_alloc(sizeof(struct pipe_content));
	work->proto_ver = MQTT_PROTOCOL_VERSION_v311;
	dbtree_create(&work->db);
	dbhash_init_pipe_table();
	// init work->msg
	nng_msg *msg;
	nng_msg_alloc(&msg,0);
	work->msg                    = msg;
	uint8_t fix_header[] = {0x30, 0x0D};
	// test data
	uint32_t remaining_len      = 13;
	uint32_t topic_len          = 7;
	uint32_t data_len           = 4;
	// topic: $MQTT
	uint8_t topic[] = {
		0x00, 0x05 /* topic length */,
		0x24, 0x4D, 0x51, 0x54, 0x54 /* topic body*/
	};
	// topic: $MQT+
	uint8_t topic_false[] = {
		0x00, 0x05 /* topic length */,
		0x24, 0x4D, 0x51, 0x54, 0x2B /* topic body*/
	};
	// data: data
	uint8_t data[] = { 0x64, 0x61, 0x74, 0x61 };
	// packetid: 5
	uint8_t pkt_id[] = { 0x00, 0x05 };
	// init msg->body and msg->header
	nng_msg_append(msg, topic, topic_len);
	nng_msg_append(msg, pkt_id, 2);
	nng_msg_append(msg, data, data_len);
	nng_msg_header_append(msg, fix_header, 2);
	
	rc = handle_pub(work, work->pipe_ct, work->proto_ver, true);
	assert(rc == 0);

	free_pub_packet(work->pub_packet);
	dbhash_destroy_pipe_table();
	dbtree_destory(work->db);
	nng_msg_free(msg);
	nng_free(work->pipe_ct,sizeof(struct pipe_content));
	nng_free(work, sizeof(*work));

	return;
}

// Regression for issue #658: with the auth http section enabled but all
// sub requests disabled (the default config template), a v5 PUBLISH that
// reuses a topic alias (empty topic name) must not be rejected by the
// ACL topic parsing, and must be resolved back to the aliased topic.
void
test_pub_v5_topic_alias_all_auth_disabled()
{
	conf *cfg = nng_zalloc(sizeof(conf));
	conf_init(cfg);
	// mimic the reported config: the auth.http_auth section is present
	// so its top-level enable flag ends up true, every sub request is
	// disabled, yet urls are configured. The entry guard must honor the
	// per-request enable flags: checking the urls alone would still run
	// the ACL flow below and reject the empty topic of msg2 (#658)
	cfg->auth_http.enable         = true;
	cfg->auth_http.super_req.url  = nng_strdup("http://127.0.0.1:8080/super");
	cfg->auth_http.acl_req.url    = nng_strdup("http://127.0.0.1:8080/acl");
	cfg->max_topic_alias          = 5;

	nano_work *work = nng_zalloc(sizeof(*work));
	dbhash_init_pipe_table();
	// the topic alias table is a global hash initialized once at broker
	// startup (broker.c), mirror it here for the alias insert/lookup
	dbhash_init_alias_table();

	nng_msg *msg1, *msg2;
	build_v5_pub_msg(&msg1, "alias/reuse/test", 1, "message-1");
	build_v5_pub_msg(&msg2, "", 1, "message-2");

	// first message establishes topic alias 1
	init_v5_pub_work(work, cfg, 0x65801, msg1);
	reason_code rc = handle_pub(work, work->pipe_ct, work->proto_ver, false);
	assert(rc == SUCCESS);
	free_pub_packet(work->pub_packet);
	work->pub_packet = NULL;

	// second message carries an empty topic and reuses topic alias 1
	work->msg = msg2;
	nng_msg_set_conn_param(msg2, work->cparam);
	rc        = handle_pub(work, work->pipe_ct, work->proto_ver, false);
	assert(rc == SUCCESS);
	assert(work->pub_packet->var_header.publish.topic_name.body != NULL);
	assert(strcmp(work->pub_packet->var_header.publish.topic_name.body,
	           "alias/reuse/test") == 0);

	nng_msg_free(msg1);
	release_v5_pub_work(work);
	dbhash_destroy_pipe_table();
	dbhash_destroy_alias_table();
	conf_fini(cfg);
}

// Regression for issue #658: with the acl sub request truly enabled, the
// ACL check must run on the resolved topic (after topic alias lookup),
// not on the raw empty topic of an alias-reusing v5 PUBLISH. The endpoint
// below refuses connections, so the publish is denied by the ACL request
// itself; the important part is that the topic has been resolved before
// the ACL stage sees it.
void
test_pub_v5_topic_alias_auth_enabled()
{
	conf *cfg = nng_zalloc(sizeof(conf));
	conf_init(cfg);
	cfg->auth_http.enable        = true;
	cfg->auth_http.acl_req.enable = true;
	cfg->auth_http.acl_req.url    = nng_strdup("http://127.0.0.1:9/acl");
	// the hocon parser allocates the per-request mutex (conf_ver2.c);
	// conf_init does not, mirror it here (freed by conf_fini)
	nng_mtx_alloc(&cfg->auth_http.acl_req.mtx);
	cfg->max_topic_alias          = 5;

	nano_work *work = nng_zalloc(sizeof(*work));
	dbhash_init_pipe_table();
	dbhash_init_alias_table();
	// topic alias 1 was established by an earlier (allowed) publish
	dbhash_insert_atpair(0x65802, 1, "alias/reuse/test");

	nng_msg *msg2;
	build_v5_pub_msg(&msg2, "", 1, "message-2");
	init_v5_pub_work(work, cfg, 0x65802, msg2);

	reason_code rc = handle_pub(work, work->pipe_ct, work->proto_ver, false);
	assert(rc == NOT_AUTHORIZED);
	// the ACL stage must have received the resolved topic, i.e. the raw
	// empty topic must no longer be able to fail the ACL topic parsing
	assert(work->pub_packet->var_header.publish.topic_name.body != NULL);
	assert(strcmp(work->pub_packet->var_header.publish.topic_name.body,
	           "alias/reuse/test") == 0);

	release_v5_pub_work(work);
	dbhash_destroy_pipe_table();
	dbhash_destroy_alias_table();
	conf_fini(cfg);
}

int
main()
{
	int         rv      = -1;
	reason_code rv_rc   = -1;
	bool        rv_bool = false;
	// init work
	nano_work *work;
	work            = nng_zalloc(sizeof(*work));
	work->proto_ver = MQTT_PROTOCOL_VERSION_v311;

	nng_msg *msg, *tpcError_msg, *truncated_pub_msg;
	nng_msg_alloc(&msg, 0);
	nng_msg_alloc(&tpcError_msg, 0);
	nng_msg_alloc(&truncated_pub_msg, 0);

	struct pub_packet_struct *pub_packet, *tpcError_pub_packet,
	    *truncated_pub_packet;
	pub_packet            = nng_zalloc(sizeof(*pub_packet));
	tpcError_pub_packet   = nng_zalloc(sizeof(*tpcError_pub_packet));
	truncated_pub_packet  = nng_zalloc(sizeof(*truncated_pub_packet));

	work->msg        = msg;
	work->pub_packet = pub_packet;

	struct fixed_header *fix_hd = nng_alloc(sizeof(*fix_hd));
	fix_hd->qos                  = 1;
	fix_hd->packet_type          = PUBLISH;

	// test data
	uint32_t remaining_len      = 18;
	uint32_t topic_len          = 7;
	uint32_t data_len           = 4;
	// topic: $MQTT
	uint8_t topic[] = {
		0x00, 0x05 /* topic length */,
		0x24, 0x4D, 0x51, 0x54, 0x54 /* topic body*/
	};
	// topic: $MQT+
	uint8_t topic_false[] = {
		0x00, 0x05 /* topic length */,
		0x24, 0x4D, 0x51, 0x54, 0x2B /* topic body*/
	};
	// data: data
	uint8_t data[] = { 0x64, 0x61, 0x74, 0x61 };
	// packetid: 5
	uint8_t pkt_id[] = { 0x00, 0x05 };

	// init msg->body and msg->header
	nng_msg_append(msg, topic, topic_len);
	nng_msg_append(msg, pkt_id, 2);
	nng_msg_append(msg, data, data_len);
	nng_msg_header_append(msg, fix_hd, sizeof(*fix_hd));

	// init tpcError_msg->body
	nng_msg_append(tpcError_msg, topic_false, topic_len);
	// nng_msg_append(tpcError_msg, pkt_id, 2);
	nng_msg_append(tpcError_msg, data, data_len);
	nng_msg_header_append(tpcError_msg, fix_hd, sizeof(*fix_hd));


	/* test for decode_pub_message */
	// TODO test for MQTTv5
	// test for remaining_len > msg_len
	uint8_t *header = nng_msg_header(work->msg);
	*(header + 1) = 24;
	rv_rc = decode_pub_message(work, MQTT_PROTOCOL_VERSION_v311);
	assert(rv_rc == PROTOCOL_ERROR);

	// test for commom case.
	*(header + 1) = 13;
	rv_rc = decode_pub_message(work, MQTT_PROTOCOL_VERSION_v311);
	assert(rv_rc == SUCCESS);
	// check work->pub_packet
	assert(work->pub_packet->var_header.publish.topic_name.len == 5);
	assert(strcmp(work->pub_packet->var_header.publish.topic_name.body, "$MQTT") == 0);
	assert(work->pub_packet->payload.len == 4);
	assert(strcmp(pub_packet->payload.data, "data") == 0);
	assert(work->pub_packet->var_header.publish.packet_id == 5);

	// test for wrong topic body
	work->msg = tpcError_msg;
	work->pub_packet = tpcError_pub_packet;
	rv_rc = decode_pub_message(work, MQTT_PROTOCOL_VERSION_v311);
	assert(rv_rc == PROTOCOL_ERROR);

	// test for truncated QoS1 publish: topic present, packet ID missing
	// fix_hd->qos is already 1 (set above), so the decoder expects a
	// 2-byte packet identifier after the topic. With only the topic in
	// the body, decode_pub_message must return PROTOCOL_ERROR instead of
	// reading past the end of the buffer (heap-buffer-overflow fix).
	nng_msg_append(truncated_pub_msg, topic, topic_len);
	nng_msg_header_append(truncated_pub_msg, fix_hd, sizeof(*fix_hd));
	uint8_t *trunc_header = nng_msg_header(truncated_pub_msg);
	// remaining length equals topic_len: no room for a packet identifier
	*(trunc_header + 1)   = (uint8_t) topic_len;
	work->msg             = truncated_pub_msg;
	work->pub_packet      = truncated_pub_packet;
	rv_rc = decode_pub_message(work, MQTT_PROTOCOL_VERSION_v311);
	assert(rv_rc == PROTOCOL_ERROR);


	/* test for encode_pub_message() */
	// alloc dest_msg and init work
	nng_msg *dest_msg;
	nng_msg_alloc(&dest_msg, 0);
	nng_msg_set_cmd_type(dest_msg, CMD_PUBLISH);
	work->msg = msg;
	work->pub_packet = pub_packet;

	rv_bool = encode_pub_message(dest_msg, work, PUBLISH);
	assert(rv_bool == true);

	// check dest_msg
	// args to get the content of msg
	uint32_t pos            = 0;
	uint32_t dest_topic_len = 0;
	uint8_t *dest_body      = nng_msg_body(msg);
	// check topic len
	NNI_GET16(dest_body + pos, dest_topic_len);
	assert(dest_topic_len == 5);
	pos += 2;
	// check topic name
	uint8_t *dest_topic = nng_zalloc(dest_topic_len + 1);
	memcpy(dest_topic, (uint8_t *) (dest_body + pos), dest_topic_len);
	assert(strcmp(dest_topic, "$MQTT") == 0);
	pos += dest_topic_len;
	// check pkt_id
	uint32_t dest_pkt_id = 0;
	NNI_GET16(dest_body + pos, dest_pkt_id);
	assert(dest_pkt_id == 5);
	pos += 2;
	// check data
	uint32_t left_len  = nng_msg_len(dest_msg) - pos;
	uint8_t *dest_data = nng_zalloc(left_len + 1);
	memcpy(dest_data, (uint8_t *) (dest_body + pos), left_len);
	assert(strcmp(dest_data, "data") == 0);


	/* test for free_pub_packet() */
	free_pub_packet(pub_packet);
	free_pub_packet(tpcError_pub_packet);
	free_pub_packet(truncated_pub_packet);


	/* test for init_pipe_content() */
	struct pipe_content *pipe_ct = nng_zalloc(sizeof(*pipe_ct));
	init_pipe_content(pipe_ct);
	assert(pipe_ct->msg_infos == NULL);


	nng_free(pipe_ct,sizeof(*pipe_ct));
	nng_free(dest_data, left_len);
	nng_free(dest_topic, dest_topic_len);
	nng_free(fix_hd, sizeof(*fix_hd));
	nng_msg_free(dest_msg);
	nng_msg_free(msg);
	nng_msg_free(tpcError_msg);
	nng_msg_free(truncated_pub_msg);
	nng_free(work, sizeof(*work));

	test_handler_pub();
	test_pub_v5_topic_alias_all_auth_disabled();
	test_pub_v5_topic_alias_auth_enabled();

	return SUCCESS;
}