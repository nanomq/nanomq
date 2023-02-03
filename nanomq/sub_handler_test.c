#include <assert.h>
#include <stdio.h>

#include "include/nanomq.h"
#include "include/sub_handler.h"

int
main()
{
	int rv = 0;

	nano_work *work;
	nng_socket sock;
	conf      *nanomq_conf;

	/* init work */
	// sock.id = 0;
	work = nng_alloc(sizeof(*work));
	// work->pub_packet = NULL;
	work->state     = INIT;
	work->db        = NULL;
	work->db_ret    = NULL;
	work->proto     = PROTO_MQTT_BROKER;
	work->proto_ver = MQTT_PROTOCOL_VERSION_v311;
	work->config    = nanomq_conf;
	// work->code       = SUCCESS;

	// init msg.
	nng_msg *msg;
	nng_msg_alloc(&msg, 0);
	uint8_t *payload_ptr, *variable_ptr, *fix_ptr;
	size_t   remaining_len;
	payload_ptr  = NULL;
	variable_ptr = NULL;
	// set topic for test:$MQTT.
	uint8_t topic[] = { 0x00, 0x05, 0x24, 0x4D, 0x51, 0x54, 0x54, '\0',
		0x00, 0x05, 0x25, 0x4D, 0x51, 0x54, 0x54, '\0' };
	payload_ptr     = topic;
	nng_msg_set_payload_ptr(msg, payload_ptr);
	// set remaining_len.
	remaining_len = nng_msg_len(msg);
	nng_msg_set_remaining_len(msg, remaining_len);
	// set work->msg.
	work->msg = msg;
	// alloc sub_pkt.
	work->sub_pkt = nng_alloc(sizeof(packet_subscribe));

	/* test for function decode_sub_msg() */
	// test for case: packet_id == 0.
	rv = decode_sub_msg(work);
	assert(rv == PROTOCOL_ERROR);

	// test for common cases.
	// set packet_id: 0x05.
	uint8_t packet_id[2] = { 0x00, 0x05 };
	nng_msg_append(work->msg, packet_id, 2);
	remaining_len = 12;
	nng_msg_set_remaining_len(work->msg, remaining_len);

	rv = decode_sub_msg(work);
	assert(rv == 0);

	topic_node *node = work->sub_pkt->node;
	rv               = strcmp(node->topic.body, "$MQTT");
	assert(rv == 0);

	node = node->next;
	rv   = strcmp(node->topic.body, "%MQTT");
	assert(rv == 0);

	/* test for encode_suback_msg() */
	uint8_t pkt_id;
	uint8_t reason_code;
	rv = encode_suback_msg(msg, work);
	assert(rv == 0);

	variable_ptr = nng_msg_body(msg);
	NNI_GET16(variable_ptr, pkt_id);
	assert(pkt_id == 5);

	NNI_GET16(variable_ptr + 2, reason_code);
	assert(reason_code == GRANTED_QOS_2);
	
	fix_ptr = nng_msg_header(msg);
	assert(*(uint8_t *) fix_ptr == CMD_SUBACK);

	/* test for sub_ctx_handle() */
	// rv = sub_ctx_handle(work);
	// assert(rv == 0);
	// // TODO check work->db.

	/* test for sub_ctx_del()*/
	// uint8_t _topic[] = { 0x24, 0x4D, 0x51, 0x54, 0x54, '\0' };
	// rv = sub_ctx_del(work->db, _topic, work->pid.id);
	// assert(rv == 0);

	// free sub_pkt.
	sub_pkt_free(work->sub_pkt);

	nng_msg_free(msg);
	nng_free(work, sizeof(struct work));
}
