#include <assert.h>
#include <stdio.h>

#include "include/nanomq.h"
#include "include/unsub_handler.h"

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
	// set topic for test:$MQTT and %MQTT.
	uint8_t topic[] = { 0x00, 0x05, 0x24, 0x4D, 0x51, 0x54, 0x54, 0x00,
		0x05, 0x25, 0x4D, 0x51, 0x54, 0x54 };
	payload_ptr     = topic;
	nng_msg_set_payload_ptr(msg, payload_ptr);
	// set work->msg.
	work->msg = msg;
	// alloc unsub_pkt.
	work->unsub_pkt = nng_alloc(sizeof(packet_unsubscribe));

	/* test for function decode_unsub_msg() */
	uint8_t packet_id[2] = { 0x00, 0x05 };
	nng_msg_append(work->msg, packet_id, 2);
	nng_msg_append(work->msg, topic, 14);
	remaining_len = 16;
	rv = decode_unsub_msg(work);
	assert(rv == 0);

	topic_node *node = work->unsub_pkt->node;
	rv               = strncmp(node->topic.body, "$MQTT", 5);
	assert(rv == 0);
	node = node->next;
	rv   = strncmp(node->topic.body, "%MQTT", 5);
	assert(rv == 0);

	/* test for encode_unsuback_msg() */
	uint8_t pkt_id;
	uint8_t reason_code;
	rv = encode_unsuback_msg(msg, work);
	assert(rv == 0);

	variable_ptr = nng_msg_body(msg);
	NNI_GET16(variable_ptr, pkt_id);
	assert(pkt_id == 5);

	fix_ptr = nng_msg_header(msg);
	assert(*(uint8_t *) fix_ptr == CMD_UNSUBACK);

	// free unsub_pkt.
	unsub_pkt_free(work->unsub_pkt);

	nng_msg_free(msg);
	nng_free(work, sizeof(struct work));
}
