//
// Copyright 2020 NanoMQ Team, Inc. <jaylin@emqx.io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//
#include "include/unsub_handler.h"
#include "include/nanomq.h"
#include "include/sub_handler.h"
#include "nng/protocol/mqtt/mqtt_parser.h"
#include <nanolib.h>
#include <nng.h>
#include <protocol/mqtt/mqtt.h>

int
decode_unsub_msg(nano_work *work)
{
	uint8_t *variable_ptr;
	uint8_t *payload_ptr;
	uint32_t vpos = 0; // pos in variable
	uint32_t bpos = 0; // pos in payload

	uint32_t len_of_varint = 0, len_of_property = 0, len_of_properties = 0;
	uint32_t len_of_str = 0, len_of_topic;

	packet_unsubscribe *unsub_pkt     = work->unsub_pkt;
	nng_msg *           msg           = work->msg;
	size_t              remaining_len = nng_msg_remaining_len(msg);

	uint8_t property_id;
	topic_node *       tn, *_tn;

	const uint8_t proto_ver = conn_param_get_protover(work->cparam);

	// handle varibale header
	variable_ptr = nng_msg_body(msg);
	NNI_GET16(variable_ptr, unsub_pkt->packet_id);
	vpos += 2;

	unsub_pkt->properties = NULL;
	unsub_pkt->prop_len = 0;
	// Mqtt_v5 include property
	unsub_pkt->properties = NULL;
	if (PROTOCOL_VERSION_v5 == proto_ver) {
		unsub_pkt->properties =
		    decode_properties(msg, &vpos, &unsub_pkt->prop_len, false);
		if (check_properties(unsub_pkt->properties) != SUCCESS) {
			return PROTOCOL_ERROR;
		}
	}

	debug_msg("remain_len: [%ld] packet_id : [%d]", remaining_len,
	    unsub_pkt->packet_id);

	// handle payload
	payload_ptr = nng_msg_payload_ptr(msg);

	if ((tn = nng_alloc(sizeof(topic_node))) == NULL) {
		debug_msg("ERROR: nng_alloc");
		return NNG_ENOMEM;
	}
	unsub_pkt->node = tn;
	tn->next = NULL;

	while (1) {
		_tn = tn;

		len_of_topic = get_utf8_str(&tn->topic.body, payload_ptr, &bpos);
		if (len_of_topic != -1) {
			tn->topic.len = len_of_topic;
		} else {
			tn->reason_code = UNSPECIFIED_ERROR;
			debug_msg("ERROR: not utf-8 format string.");
			return PROTOCOL_ERROR;
		}

		debug_msg("bpos+vpos: [%d] remain_len: [%ld]", bpos + vpos,
		    remaining_len);
		if (bpos < remaining_len - vpos) {
			if ((tn = nng_alloc(sizeof(topic_node))) == NULL) {
				debug_msg("ERROR: nng_alloc");
				return NNG_ENOMEM;
			}
			tn->next  = NULL;
			_tn->next = tn;
		} else {
			break;
		}
	}
	return 0;
}

int
encode_unsuback_msg(nng_msg *msg, nano_work *work)
{
	nng_msg_header_clear(msg);
	nng_msg_clear(msg);

	uint8_t     packet_id[2];
	uint8_t     varint[4];
	uint8_t     reason_code, cmd, property_len = 0;
	uint32_t    remaining_len;
	int         len_of_varint, rv;
	topic_node *tn;

	packet_unsubscribe *unsub_pkt = work->unsub_pkt;
	const uint8_t       proto_ver = conn_param_get_protover(work->cparam);

	// handle variable header first
	NNI_PUT16(packet_id, unsub_pkt->packet_id);
	if ((rv = nng_msg_append(msg, packet_id, 2)) != 0) {
		debug_msg("ERROR: nng_msg_append");
		return PROTOCOL_ERROR;
	}

	if (PROTOCOL_VERSION_v5 == proto_ver) {
		//TODO set property if necessary 
		encode_properties(msg, NULL, CMD_UNSUBACK);
	}

	// handle payload
	// no payload in mqtt_v3
	if (PROTOCOL_VERSION_v5 == proto_ver) {
		tn = unsub_pkt->node;
		while (tn) {
			reason_code = tn->reason_code;
			if ((rv = nng_msg_append(
			         msg, (uint8_t *) &reason_code, 1)) != 0) {
				debug_msg("ERROR: nng_msg_append [%d]", rv);
				return PROTOCOL_ERROR;
			}
			tn = tn->next;
			debug_msg("reason_code: [%x]", reason_code);
		}
	}

	// handle fixed header
	cmd = CMD_UNSUBACK;
	if ((rv = nng_msg_header_append(msg, (uint8_t *) &cmd, 1)) != 0) {
		debug_msg("ERROR: nng_msg_header_append [%d]", rv);
		return PROTOCOL_ERROR;
	}

	remaining_len = (uint32_t) nng_msg_len(msg);
	len_of_varint = put_var_integer(varint, remaining_len);
	if ((rv = nng_msg_header_append(msg, varint, len_of_varint)) != 0) {
		debug_msg("ERROR: nng_msg_header_append [%d]", rv);
		return PROTOCOL_ERROR;
	}

	debug_msg("unsuback:"
	          " remain: [%d]"
	          " varint: [%d %d %d %d]"
	          " len: [%d]"
	          " packet_id: [%x %x]",
	    remaining_len, varint[0], varint[1], varint[2], varint[3],
	    len_of_varint, packet_id[0], packet_id[1]);

	return 0;
}

int
unsub_ctx_handle(nano_work *work)
{
	topic_node *   tn = work->unsub_pkt->node;
	char *         topic_str;
	char *         client_id;
	struct client *cli     = NULL;
	void *         cli_ctx = NULL;
	int rv;

	client_id = (char *) conn_param_get_clientid(
	    (conn_param *) nng_msg_get_conn_param(work->msg));
	uint32_t clientid_key = DJBHashn(client_id, strlen(client_id));

	// delete ctx_unsub in treeDB
	while (tn) {
		if (tn->topic.len == 0) {
			tn = tn->next;
			continue;
		}

		// parse topic string
		topic_str = strndup(tn->topic.body, tn->topic.len);
		debug_msg(
		    "find client [%s] in topic [%s].", client_id, topic_str);

		rv = sub_ctx_del(work->db, topic_str, work->pid.id);

		if (rv == 0) { // find the topic
			tn->reason_code = 0x00;
			debug_msg("find and delete this client.");
		} else { // not find the topic
			tn->reason_code = 0x11;
			debug_msg("not find and response ack.");
		}

		// free local varibale
		nng_free(topic_str, tn->topic.len + 1);

		tn = tn->next;
	}

	// check treeDB
	//	print_db_tree(work->db);

	debug_msg("end of unsub ctx handle.\n");
	return 0;
}

void
unsub_pkt_free(packet_unsubscribe *unsub_pkt)
{
	if (!unsub_pkt) {
		debug_msg("ERROR : ctx->sub is nil");
		return;
	}
	if (!unsub_pkt->node) {
		debug_msg("ERROR : not find topic");
		return;
	}

	if (unsub_pkt->prop_len != 0) {
		property_free(unsub_pkt->properties);
		unsub_pkt->properties = NULL;
		unsub_pkt->prop_len = 0;
	}

	topic_node *tn = unsub_pkt->node;
	topic_node *next_tn;
	while (tn) {
		next_tn = tn->next;
		nng_free(tn, sizeof(topic_node));
		tn = next_tn;
	}

	if (unsub_pkt->node == NULL) {
		nng_free(unsub_pkt, sizeof(packet_unsubscribe));
		unsub_pkt = NULL;
	}
}
