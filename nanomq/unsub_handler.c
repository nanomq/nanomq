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
#include <nanolib.h>
#include <nng.h>
#include <protocol/mqtt/mqtt.h>
#include <protocol/mqtt/mqtt_parser.h>

uint8_t
decode_unsub_message(nano_work *work)
{
	uint8_t *variable_ptr;
	uint8_t *payload_ptr;
	uint32_t vpos = 0; // pos in variable
	uint32_t bpos = 0; // pos in payload

	uint32_t len_of_varint = 0, len_of_property = 0, len_of_properties = 0;
	uint32_t len_of_str, len_of_topic;

	packet_unsubscribe *unsub_pkt     = work->unsub_pkt;
	nng_msg *           msg           = work->msg;
	size_t              remaining_len = nng_msg_remaining_len(msg);

	uint8_t property_id;

	topic_node *  topic_node_t, *_topic_node;
	const uint8_t proto_ver = conn_param_get_protover(work->cparam);

	// handle varibale header
	variable_ptr = nng_msg_body(msg);
	NNI_GET16(variable_ptr, unsub_pkt->packet_id);
	vpos += 2;

	// Mqtt_v5 include property
#if SUPPORT_MQTT5_0
	if (PROTOCOL_VERSION_v5 == proto_ver) {
		// length of property in variable
		len_of_properties =
		    get_var_integer(variable_ptr, &len_of_varint);
		vpos += len_of_varint;

		if (len_of_properties > 0) {
			while (1) {
				property_id = variable_ptr[vpos];
				switch (property_id) {
				case USER_PROPERTY:
					// key
					len_of_str = get_utf8_str(
					    &(unsub_pkt->user_property.strpair
					            .key),
					    variable_ptr, &vpos);
					unsub_pkt->user_property.strpair
					    .len_key = len_of_str;
					// value
					len_of_str = get_utf8_str(
					    &(unsub_pkt->user_property.strpair
					            .val),
					    variable_ptr, &vpos);
					unsub_pkt->user_property.strpair
					    .len_val = len_of_str;
				default:
					if (vpos > remaining_len) {
						debug_msg("ERROR_IN_LEN_VPOS");
					}
				}
			}
		}
	}
#endif

	debug_msg("remain_len: [%ld] packet_id : [%d]", remaining_len,
	    unsub_pkt->packet_id);

	// handle payload
	payload_ptr = nng_msg_payload_ptr(msg);

	debug_msg("V:[%x %x %x %x] P:[%x %x %x %x].", variable_ptr[0],
	    variable_ptr[1], variable_ptr[2], variable_ptr[3], payload_ptr[0],
	    payload_ptr[1], payload_ptr[2], payload_ptr[3]);

	if ((topic_node_t = nng_alloc(sizeof(topic_node))) == NULL) {
		debug_msg("ERROR: nng_alloc");
		return NNG_ENOMEM;
	}
	unsub_pkt->node    = topic_node_t;
	topic_node_t->next = NULL;

	while (1) {
		topic_with_option *topic_option;
		if ((topic_option = nng_alloc(sizeof(topic_with_option))) ==
		    NULL) {
			debug_msg("ERROR: nng_alloc");
			return NNG_ENOMEM;
		}
		topic_node_t->it = topic_option;
		_topic_node      = topic_node_t;

		len_of_topic = get_utf8_str(&(topic_option->topic_filter.body),
		    payload_ptr, &bpos); // len of topic filter
		if (len_of_topic != -1) {
			topic_option->topic_filter.len = len_of_topic;
		} else {
			debug_msg("ERROR: not utf-8 format string.");
			return PROTOCOL_ERROR;
		}

		debug_msg("bpos+vpos: [%d] remain_len: [%ld]", bpos + vpos,
		    remaining_len);
		if (bpos < remaining_len - vpos) {
			if ((topic_node_t = nng_alloc(sizeof(topic_node))) ==
			    NULL) {
				debug_msg("ERROR: nng_alloc");
				return NNG_ENOMEM;
			}
			topic_node_t->next = NULL;
			_topic_node->next  = topic_node_t;
		} else {
			break;
		}
	}
	return SUCCESS;
}

uint8_t
encode_unsuback_message(nng_msg *msg, nano_work *work)
{
	nng_msg_clear(msg);

	uint8_t     packet_id[2];
	uint8_t     varint[4];
	uint8_t     reason_code, cmd, property_len = 0;
	uint32_t    remaining_len;
	int         len_of_varint, rv;
	topic_node *node;

	packet_unsubscribe *unsub_pkt = work->unsub_pkt;
	const uint8_t       proto_ver = conn_param_get_protover(work->cparam);

	// handle variable header first
	NNI_PUT16(packet_id, unsub_pkt->packet_id);
	if ((rv = nng_msg_append(msg, packet_id, 2)) != 0) {
		debug_msg("ERROR: nng_msg_append");
		return PROTOCOL_ERROR;
	}

#if SUPPORT_MQTT5_0
	if (PROTOCOL_VERSION_v5 == proto_ver) {
		nng_msg_append(msg, property_len, 1);
	}

	// handle payload
	// no payload in mqtt_v3
	if (PROTOCOL_VERSION_v5 == proto_ver) {
		node = unsub_pkt->node;
		while (node) {
			reason_code = node->it->reason_code;
			if ((rv = nng_msg_append(
			         msg, (uint8_t *) &reason_code, 1)) != 0) {
				debug_msg("ERROR: nng_msg_append [%d]", rv);
				return PROTOCOL_ERROR;
			}
			node = node->next;
			debug_msg("reason_code: [%x]", reason_code);
		}
	}
#endif

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

	return SUCCESS;
}

uint8_t
unsub_ctx_handle(nano_work *work)
{
	topic_node *   topic_node_t = work->unsub_pkt->node;
	char *         topic_str;
	char *         client_id;
	struct client *cli     = NULL;
	void *         cli_ctx = NULL;

	// delete ctx_unsub in treeDB
	while (topic_node_t) {
		client_id = (char *) conn_param_get_clientid(
		    (conn_param *) nng_msg_get_conn_param(work->msg));
		uint32_t clientid_key = DJBHashn(client_id, strlen(client_id));

		// parse topic string
		topic_str =
		    (char *) nng_alloc(topic_node_t->it->topic_filter.len + 1);
		strncpy(topic_str, topic_node_t->it->topic_filter.body,
		    topic_node_t->it->topic_filter.len);
		topic_str[topic_node_t->it->topic_filter.len] = '\0';

		debug_msg(
		    "find client [%s] in topic [%s].", client_id, topic_str);

		cli_ctx = dbtree_delete_client(work->db, topic_str, clientid_key, work->pid.id);
		dbhash_del_topic(work->pid.id, topic_str);

		if (cli_ctx != NULL) { // find the topic
			topic_node_t->it->reason_code = 0x00;
			debug_msg("find and delete this client.");
		} else { // not find the topic
			topic_node_t->it->reason_code = 0x11;
			debug_msg("not find and response ack.");
		}
		del_sub_ctx(cli_ctx, topic_str);

		// free local varibale
		nng_free(topic_str, topic_node_t->it->topic_filter.len + 1);

		topic_node_t = topic_node_t->next;
	}

	// check treeDB
	//	print_db_tree(work->db);

	debug_msg("end of unsub ctx handle.\n");
	return SUCCESS;
}

void
destroy_unsub_ctx(packet_unsubscribe *unsub_pkt)
{
	if (!unsub_pkt) {
		debug_msg("ERROR : ctx->sub is nil");
		return;
	}
	if (!(unsub_pkt->node->it)) {
		debug_msg("ERROR : not find topic");
		return;
	}

	topic_node *topic_node_t = unsub_pkt->node;
	topic_node *next_topic_node;
	while (topic_node_t) {
		next_topic_node = topic_node_t->next;
		nng_free(topic_node_t->it, sizeof(topic_with_option));
		nng_free(topic_node_t, sizeof(topic_node));
		topic_node_t = next_topic_node;
	}

	if (unsub_pkt->node == NULL) {
		nng_free(unsub_pkt, sizeof(packet_unsubscribe));
		unsub_pkt = NULL;
	}
}
