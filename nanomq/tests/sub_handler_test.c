#include <assert.h>
#include <stdio.h>

#include "include/nanomq.h"
#include "include/sub_handler.h"
#include "nng/supplemental/nanolib/mqtt_db.h"
#include "nng/supplemental/nanolib/hash_table.h"

int
main()
{
	u_int32_t rv = 0;
	u_int32_t *p_rv = NULL;

	nano_work *work;
	nng_socket sock;
	conf      *nanomq_conf = nng_zalloc(sizeof(conf));
	nanomq_conf->acl.enable = false;

	/* init work */
	// sock.id = 0;
	work = nng_alloc(sizeof(*work));
	// work->pub_packet = NULL;
	work->state     = INIT;
	work->db        = NULL;
	work->db_ret    = NULL;
	work->cparam    = NULL;
	work->proto     = PROTO_MQTT_BROKER;
	work->proto_ver = MQTT_PROTOCOL_VERSION_v311;
	work->config    = nanomq_conf;
	work->pid.id    = 2;
	// work->code       = SUCCESS;
	// init dbtree
	dbtree_create(&work->db);
	dbtree_create(&work->db_ret);
	dbhash_init_pipe_table();

	// init msg.
	nng_msg *msg;
	nng_msg_alloc(&msg, 0);
	uint8_t *payload_ptr, *variable_ptr, *fix_ptr;
	size_t   remaining_len;
	payload_ptr  = NULL;
	variable_ptr = NULL;
	// topic for test:$MQTT.
	uint8_t topic[] = { 0x00, 0x05/* topic length */, 0x24, 0x4D, 0x51, 0x54, 0x54/* topic body*/, 0x00/* topic option*/,
	 0x00, 0x05, 0x25, 0x4D, 0x51, 0x54, 0x54, 0x00 };
	payload_ptr       = topic;
	nng_msg_set_payload_ptr(msg, payload_ptr);
	// set remaining_len.
	remaining_len = nng_msg_len(msg);
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
	nng_msg_append(msg, topic, 16);
	remaining_len = 12;

	rv = decode_sub_msg(work);
	assert(rv == 0);

	topic_node *node = work->sub_pkt->node;
	rv               = strncmp(node->topic.body, "$MQTT", 5);
	assert(rv == 0);

	node = node->next;
	rv   = strncmp(node->topic.body, "%MQTT", 5);
	assert(rv == 0);

	/* test for encode_suback_msg() */
	// TODO more false cases should be tested (in new test frame).
	uint8_t pkt_id;
	uint8_t reason_code;
	nng_msg *ack_msg;
	nng_msg_alloc(&ack_msg,0);
	rv = encode_suback_msg(ack_msg, work);
	assert(rv == 0);

	variable_ptr = nng_msg_body(ack_msg);
	NNI_GET16(variable_ptr, pkt_id);
	assert(pkt_id == 5);

	NNI_GET16(variable_ptr + 2, reason_code);
	assert(reason_code == GRANTED_QOS_0);

	fix_ptr = nng_msg_header(ack_msg);
	assert(*(uint8_t *) fix_ptr == CMD_SUBACK);

	/* test for sub_ctx_handle() */
	rv = sub_ctx_handle(work);
	assert(rv == 0);
	// TODO check work->db.
	dbtree_print(work->db);
	p_rv = dbtree_find_clients(work->db, "$MQTT");
	assert(p_rv != NULL);
	cvector_free(p_rv);

	p_rv = dbtree_find_clients(work->db, "%MQTT");
	assert(p_rv != NULL);
	cvector_free(p_rv);
	// TODO should free by dbtree_delete_client() and dbhash_del_topic()

	/* test for sub_ctx_del()*/
	uint8_t del_topic_1[] = { 0x24, 0x4D, 0x51, 0x54, 0x54, 0x00 };
	uint8_t del_topic_2[] = { 0x25, 0x4D, 0x51, 0x54, 0x54, 0x00 };
	rv = sub_ctx_del(work->db, del_topic_1, work->pid.id);
	assert(rv == 0);
	rv = sub_ctx_del(work->db, del_topic_2, work->pid.id);
	assert(rv == 0);

	/* test for free sub_pkt() */
	sub_pkt_free(work->sub_pkt);

	nng_free(nanomq_conf, sizeof(conf));
	dbhash_destroy_pipe_table();
	dbtree_destory(work->db);
	dbtree_destory(work->db_ret);
	nng_msg_free(ack_msg);
	nng_msg_free(msg);
	nng_free(work, sizeof(struct work));
}
