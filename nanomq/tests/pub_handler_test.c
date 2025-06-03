#include <assert.h>
#include <stdio.h>

#include "include/nanomq.h"
#include "include/pub_handler.h"

void
test_handler_pub()
{
	reason_code rc = 0;
	// init work
	nano_work *work;
	work            = nng_alloc(sizeof(*work));
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

int
main()
{
	int         rv      = -1;
	reason_code rv_rc   = -1;
	bool        rv_bool = false;
	// init work
	nano_work *work;
	work            = nng_alloc(sizeof(*work));
	work->proto_ver = MQTT_PROTOCOL_VERSION_v311;

	nng_msg *msg, *tpcError_msg;
	nng_msg_alloc(&msg, 0);
	nng_msg_alloc(&tpcError_msg, 0);

	struct pub_packet_struct *pub_packet, *tpcError_pub_packet;
	pub_packet          = nng_zalloc(sizeof(*pub_packet));
	tpcError_pub_packet = nng_zalloc(sizeof(*tpcError_pub_packet));

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
	nng_free(work, sizeof(*work));

	test_handler_pub();

	return SUCCESS;
}