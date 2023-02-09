#include <assert.h>
#include <stdio.h>

#include "include/nanomq.h"
#include "include/pub_handler.h"

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

	nng_msg *msg;
	nng_msg_alloc(&msg, 0);

	struct pub_packet_struct *pub_packet;
	pub_packet                  = nng_zalloc(sizeof(*pub_packet));

	work->msg                   = msg;
	work->pub_packet            = pub_packet;

	struct fixed_header *fix_hd = nng_alloc(sizeof(*fix_hd));
	fix_hd->qos                 = 0;
	fix_hd->packet_type         = PUBLISH;

	// test data
	uint32_t remaining_len      = 18;
	uint32_t topic_len          = 7;
	uint32_t data_len           = 4;
	// topic: $MQTT
	uint8_t topic[] = {
		0x00, 0x05 /* topic length */, 0x24, 0x4D, 0x51, 0x54,
		0x54 /* topic body*/
	};
	// data: data
	uint8_t data[] = { 0x64, 0x61, 0x74, 0x61 };

	// init msg->body and msg->header
	nng_msg_append(work->msg, topic, topic_len);
	nng_msg_append(work->msg, data, data_len);
	nng_msg_set_remaining_len(work->msg, remaining_len);
	nng_msg_header_append(work->msg, fix_hd, sizeof(*fix_hd));

	/* test for decode_pub_message */
	// TODO test for MQTTv5
	// test for remaining_len > msg_len
	rv_rc = decode_pub_message(work, MQTT_PROTOCOL_VERSION_v311);
	assert(rv_rc == PROTOCOL_ERROR);
	// test for commom case.
	remaining_len = 11;
	nng_msg_set_remaining_len(work->msg, remaining_len);
	rv_rc = decode_pub_message(work, MQTT_PROTOCOL_VERSION_v311);
	assert(rv_rc == SUCCESS);
	// check work->pub_packet
	assert(work->pub_packet->var_header.publish.topic_name.len == 5);
	assert(strcmp(work->pub_packet->var_header.publish.topic_name.body,
	           "$MQTT") == 0);
	assert(work->pub_packet->payload.len == 4);
	assert(strcmp(pub_packet->payload.data, "data") == 0);

	/* test for encode_pub_message() */
	// alloc dest_msg
	nng_msg *dest_msg;
	nng_msg_alloc(&dest_msg, 0);
	nng_msg_set_cmd_type(dest_msg, CMD_PUBLISH);
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
	// check data
	uint32_t left_len  = nng_msg_len(dest_msg) - pos;
	uint8_t *dest_data = nng_zalloc(left_len + 1);
	memcpy(dest_data, (uint8_t *) (dest_body + pos), left_len);
	assert(strcmp(dest_data, "data") == 0);

	/* test for free_pub_packet() */
	free_pub_packet(pub_packet);

	nng_free(dest_data, left_len);
	nng_free(dest_topic, dest_topic_len);
	nng_free(fix_hd, sizeof(*fix_hd));
	nng_msg_free(dest_msg);
	nng_msg_free(msg);
	nng_free(work, sizeof(*work));

	return SUCCESS;
}