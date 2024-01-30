// Copyright 2023 NanoMQ Team, Inc. <jaylin@emqx.io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//
#include "nng/nng.h"
#include "nng/mqtt/packet.h"
#include "nng/protocol/mqtt/mqtt_parser.h"
#include "nng/supplemental/nanolib/nanolib.h"
#include "nng/supplemental/util/platform.h"
#include "nng/supplemental/nanolib/log.h"
#include "nng/supplemental/nanolib/conf.h"

#include "include/broker.h"
#include "include/nanomq.h"
#include "include/pub_handler.h"
#include "include/sub_handler.h"
#include "include/acl_handler.h"

/**
 * @brief decode msg in work->payload to create topic_nodes.
 * @param work nano_work
 * @return error code
 */
int
decode_sub_msg(nano_work *work)
{
	uint8_t *variable_ptr, *payload_ptr;
	int      vpos          = 0; // pos in variable
	int      bpos          = 0; // pos in payload
	size_t   len_of_varint = 0, len_of_property = 0, len_of_properties = 0;
	int      len_of_str = 0, len_of_topic = 0;
	uint8_t  property_id;

	topic_node *       tn, *_tn;

	nng_msg *     msg           = work->msg;
	size_t        remaining_len = nng_msg_remaining_len(msg);
	const uint8_t proto_ver     = work->proto_ver;

	// handle variable header
	variable_ptr = nng_msg_body(msg);

	packet_subscribe *sub_pkt = work->sub_pkt;
	sub_pkt->node = NULL;
	NNI_GET16(variable_ptr + vpos, sub_pkt->packet_id);
	if (sub_pkt->packet_id == 0)
		return PROTOCOL_ERROR; // packetid should be non-zero
	// TODO packetid should be checked if it's unused
	vpos += 2;

	sub_pkt->properties = NULL;
	sub_pkt->prop_len   = 0;
	// Only Mqtt_v5 include property.
	if (MQTT_PROTOCOL_VERSION_v5 == proto_ver) {
		sub_pkt->properties =
		    decode_properties(msg, (uint32_t *)&vpos, &sub_pkt->prop_len, true);
		if (check_properties(sub_pkt->properties) != SUCCESS) {
			return PROTOCOL_ERROR;
		}
	}

	log_debug("remainLen: [%ld] packetid : [%d]", remaining_len,
	    sub_pkt->packet_id);
	// handle payload
	payload_ptr = nng_msg_payload_ptr(msg);

	if ((tn = nng_zalloc(sizeof(topic_node))) == NULL) {
		log_error("nng_zalloc");
		return NNG_ENOMEM;
	}
	tn->next = NULL;
	sub_pkt->node      = tn;

	while (1) {
		_tn      = tn;

		tn->reason_code  = GRANTED_QOS_2; // default

		// TODO Decoding topic has potential buffer overflow
		tn->topic.body = (char *) copyn_utf8_str(payload_ptr,
		    (uint32_t *) &bpos, &len_of_topic, remaining_len);
		tn->topic.len  = len_of_topic;
		log_info("topic: [%s] len: [%d] pid [%d]", tn->topic.body, len_of_topic, sub_pkt->packet_id);
		len_of_topic = 0;

		if (tn->topic.len < 1 || tn->topic.body == NULL) {
			log_error("NOT utf8-encoded string OR null string.");
			tn->reason_code = UNSPECIFIED_ERROR;
			if (MQTT_PROTOCOL_VERSION_v5 == proto_ver)
				tn->reason_code = TOPIC_FILTER_INVALID;
			bpos += 1; // ignore option
			goto next;
		}

		tn->rap = 1; // Default Setting
		memcpy(tn, payload_ptr + bpos, 1);
		if (tn->retain_handling > 2) {
			log_error("error in retain_handling");
			tn->reason_code = UNSPECIFIED_ERROR;
			return PROTOCOL_ERROR;
		}
		bpos ++;

		// Setting no_local on shared subscription is invalid
		if (MQTT_VERSION_V5 == proto_ver &&
		    strncmp(tn->topic.body, "$share/", strlen("$share/")) == 0 &&
		    tn->no_local == 1) {
			tn->reason_code = UNSPECIFIED_ERROR;
			return PROTOCOL_ERROR;
		}

next:
		if (bpos < (int) (remaining_len - vpos)) {
			if (NULL == (tn = nng_zalloc(sizeof(topic_node)))) {
				log_error("nng_zalloc");
				return NNG_ENOMEM;
			}
			tn->next = NULL;
			_tn->next  = tn;
		} else {
			break;
		}
	}
	return 0;
}

/**
 * @brief encode a suback nng_msg via nano_work.
 * @param msg suback nng_msg
 * @param work nano_work
 * @return error code
 */
int
encode_suback_msg(nng_msg *msg, nano_work *work)
{
	nng_msg_header_clear(msg);
	nng_msg_clear(msg);

	uint8_t     packet_id[2];
	uint8_t     varint[4];
	uint8_t     reason_code, cmd;
	uint32_t    remaining_len, len_of_properties;
	int         len_of_varint, rv;
	topic_node *tn;

	packet_subscribe *sub_pkt;
	if ((sub_pkt = work->sub_pkt) == NULL)
		return (-1);

	const uint8_t proto_ver = work->proto_ver;

	// handle variable header first
	NNI_PUT16(packet_id, sub_pkt->packet_id);
	if ((rv = nng_msg_append(msg, packet_id, 2)) != 0) {
		log_error("nng_msg_append [%d]", rv);
		return PROTOCOL_ERROR;
	}

	if (MQTT_PROTOCOL_VERSION_v5 == proto_ver) { // add property in variable
		encode_properties(msg, NULL, CMD_SUBACK);
	}

	// Note. packetid should be non-zero, BUT in order to make subclients
	// known that, we return an error(ALREADY IN USE)
	reason_code = PACKET_IDENTIFIER_IN_USE;
	if (sub_pkt->packet_id == 0) {
		if ((rv = nng_msg_append(msg, &reason_code, 1)) != 0) {
			log_error("nng_msg_append [%d]", rv);
			return PROTOCOL_ERROR;
		}
	}

	// Note. When packet_id is zero, topic node must be empty. So, Dont worry
	// about that the order of reason codes would be changed.
	// handle payload
	tn = sub_pkt->node;
	while (tn) {
		reason_code = tn->reason_code;
		// MQTT_v3: 0x00-qos0  0x01-qos1  0x02-qos2  0x80-fail
		if ((rv = nng_msg_append(msg, &reason_code, 1)) != 0) {
			log_error("nng_msg_append [%d]", rv);
			return PROTOCOL_ERROR;
		}
		tn = tn->next;
		log_debug("reason_code: [%x]", reason_code);
	}

	// If NOT find any reason codes
	if (!sub_pkt->node && sub_pkt->packet_id != 0) {
		reason_code = UNSPECIFIED_ERROR;
		if ((rv = nng_msg_append(msg, &reason_code, 1)) != 0) {
			log_error("nng_msg_append [%d]", rv);
			return PROTOCOL_ERROR;
		}
	}

	// handle fixed header
	cmd = CMD_SUBACK;
	if ((rv = nng_msg_header_append(msg, (uint8_t *) &cmd, 1)) != 0) {
		log_error("nng_msg_header_append [%d]", rv);
		return PROTOCOL_ERROR;
	}

	remaining_len = (uint32_t) nng_msg_len(msg);
	len_of_varint = put_var_integer(varint, remaining_len);
	if ((rv = nng_msg_header_append(msg, varint, len_of_varint)) != 0) {
		log_error("nng_msg_header_append [%d]", rv);
		return PROTOCOL_ERROR;
	}

	log_debug("remain: [%d] "
	          "varint: [%d %d %d %d] "
	          "len: [%d] "
	          "packetid: [%x %x] ",
	    remaining_len, varint[0], varint[1], varint[2], varint[3],
	    len_of_varint, packet_id[0], packet_id[1]);

	return 0;
}

// generate ctx for each topic
// this should be moved to RECV
int
sub_ctx_handle(nano_work *work)
{
	if (!work->sub_pkt || !work->sub_pkt->node) {
		return -1;
	}
	topic_node *tn = work->sub_pkt->node;

	char *topic_str = NULL;
	int   topic_len = 0, topic_exist = 0;

	if (work->sub_pkt->packet_id == 0) {
		return -2;
	}

#ifdef STATISTICS
	// TODO
#endif
	nng_msg **retain = work->msg_ret;
	while (tn) {
		topic_len = tn->topic.len;
		topic_str = tn->topic.body;
		log_debug("topicLen: [%d] body: [%s]", topic_len, topic_str);

		if (!topic_str)
			goto next;
#ifdef ACL_SUPP
		/* Add items which not included in dbhash */
		if (work->config->acl.enable) {
			bool auth_result = auth_acl(
			    work->config, ACL_SUB, work->cparam, topic_str);
			if (!auth_result) {
				log_warn("acl deny");
				tn->reason_code = NMQ_AUTH_SUB_ERROR;
				if (work->config->acl_deny_action ==
				    ACL_DISCONNECT) {
					log_warn("acl deny, disconnect client");
					// TODO disconnect client or return error code
					goto next;
				} else if (work->config->acl_deny_action ==
				    ACL_IGNORE) {
					log_warn("acl deny, ignore");
					goto next;
				}
			} else {
				log_info("acl allow");
			}
		}
#endif

		topic_exist = dbhash_check_topic(work->pid.id, topic_str);
		if (!topic_exist) {
			dbtree_insert_client(
			    work->db, topic_str, work->pid.id);

			dbhash_insert_topic(work->pid.id, topic_str, tn->qos);
		}

		// Note.
		// if topic already exists then update sub options.
		// qos, retain handling, no local (already did in protocol
		// layer)

		// Retain msg
		uint8_t rh = tn->retain_handling;

#if defined(NNG_SUPP_SQLITE)
		if (work->config->sqlite.enable && work->sqlite_db != NULL) {
			if (rh == 0 || (rh == 1 && !topic_exist)) {
				nng_msg **msg_vec =
				    nng_mqtt_qos_db_find_retain(
				        work->sqlite_db, topic_str);

				if (msg_vec != NULL) {
					for (size_t i = 0;
					     i < cvector_size(msg_vec); i++) {
						if (msg_vec[i] != NULL) {
							cvector_push_back(
							    work->msg_ret,
							    msg_vec[i]);
						}
					}
					cvector_free(msg_vec);
				}
			}
			goto next;
		}
#endif
		if (rh == 0 || (rh == 1 && !topic_exist))
			retain = dbtree_find_retain(work->db_ret, topic_str);
		work->msg_ret = (work->msg_ret == NULL) ? retain : work->msg_ret;

		for (size_t i = 0; retain != NULL &&
		     i < cvector_size(retain) && work->msg_ret != retain;
		     i++) {
			if (!retain[i])
				continue;
			cvector_push_back(work->msg_ret, retain[i]);
		}
		if (retain != work->msg_ret) {
			cvector_free(retain);
			retain = NULL;
		}
		

		if (!work->msg_ret)
			goto next;

	next:
		tn = tn->next;
	}

#ifdef DEBUG
	dbtree_print(work->db);
#endif
	log_debug("end of sub ctx handle.\n");
	return 0;
}

int
sub_ctx_del(void *db, char *topic, uint32_t pid)
{
	dbtree_delete_client((dbtree *)db, topic, pid);

	dbhash_del_topic(pid, topic);

	return 0;
}

static void *
destroy_sub_client_cb(void *args, char *topic)
{
	sub_destroy_info *des = (sub_destroy_info *) args;

	dbtree_delete_client(des->db, topic, des->pid);

	return NULL;
}

// Call by disconnect ev, if disconnect, delete all node which 
// this pipe subscribed on tree and topic_queue,  free db_ctxt,
// if it's ref == 0 delete it.
void
destroy_sub_client(uint32_t pid, dbtree * db)
{
	sub_destroy_info sdi = {
		.pid = pid,
		.db = db,
	};

	dbhash_del_topic_queue(pid, &destroy_sub_client_cb, (void *) &sdi);

	return;
}

void
sub_pkt_free(packet_subscribe *sub_pkt)
{
	if (!sub_pkt)
		return;

	topic_node *tn, *next_tn;
	tn = sub_pkt->node;
	next_tn = NULL;

	while (tn) {
		next_tn = tn->next;
		nng_free(tn->topic.body, tn->topic.len);
		nng_free(tn, sizeof(topic_node));
		tn = next_tn;
	}

	// what if there are multiple UPs?
	if (sub_pkt->prop_len > 0) {
		property_free(sub_pkt->properties);
		sub_pkt->prop_len = 0;
	}
	nng_free(sub_pkt, sizeof(packet_subscribe));
}

