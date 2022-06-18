// Copyright 2020 NanoMQ Team, Inc. <jaylin@emqx.io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//
#include <nanolib.h>
#include <nng.h>
#include <nng/mqtt/packet.h>
#include "nng/protocol/mqtt/mqtt_parser.h"
#include "nng/supplemental/util/platform.h"

#include "include/broker.h"
#include "include/nanomq.h"
#include "include/pub_handler.h"
#include "include/sub_handler.h"

#define SUPPORT_MQTT5_0 1

static void cli_ctx_merge(client_ctx *ctx, client_ctx *ctx_new);

int
decode_sub_msg(nano_work *work)
{
	uint8_t *variable_ptr, *payload_ptr;
	int      vpos          = 0; // pos in variable
	int      bpos          = 0; // pos in payload
	size_t   len_of_varint = 0, len_of_property = 0, len_of_properties = 0;
	int      len_of_str = 0, len_of_topic = 0;
	uint8_t  property_id;

	topic_node *       topic_node_t, *_topic_node;
	topic_with_option *topic_option;

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

#if SUPPORT_MQTT5_0
	// Only Mqtt_v5 include property.
	if (PROTOCOL_VERSION_v5 == proto_ver) {
		sub_pkt->properties =
		    decode_properties(msg, &vpos, &sub_pkt->prop_len, true);
		if (check_properties(sub_pkt->properties) != SUCCESS) {
			return PROTOCOL_ERROR;
		}
	}
#endif

	debug_msg("remainLen: [%ld] packetid : [%d]", remaining_len,
	    sub_pkt->packet_id);
	// handle payload
	payload_ptr = nng_msg_payload_ptr(msg);

	if ((topic_node_t = nng_zalloc(sizeof(topic_node))) == NULL) {
		debug_msg("ERROR: nng_zalloc");
		return NNG_ENOMEM;
	}
	topic_node_t->next = NULL;
	sub_pkt->node      = topic_node_t;

	while (1) {
		if ((topic_option = nng_zalloc(sizeof(topic_with_option))) ==
		    NULL) {
			debug_msg("ERROR: nng_zalloc");
			return NNG_ENOMEM;
		}
		topic_node_t->it = topic_option;
		_topic_node      = topic_node_t;

		// potential buffer overflow
		topic_option->topic_filter.body =
		    copy_utf8_str(payload_ptr, &bpos, &len_of_topic);

		topic_option->topic_filter.len = len_of_topic;
		topic_node_t->it->reason_code  = GRANTED_QOS_2; // default

		if (len_of_topic < 1 || topic_option->topic_filter.body == NULL) {
			debug_msg("NOT utf8-encoded string OR null string.");
			topic_node_t->it->reason_code = UNSPECIFIED_ERROR;
			if (PROTOCOL_VERSION_v5 == proto_ver)
				topic_node_t->it->reason_code =
				    TOPIC_FILTER_INVALID;
			bpos += 3; // ignore option + LSB + MSB
			goto next;
		}
		debug_msg("topic: [%s] len: [%d]",
		    topic_option->topic_filter.body, len_of_topic);
		len_of_topic = 0;

		topic_option->rap = 1; // Default Setting
		memcpy(topic_option, payload_ptr + bpos, 1);
		if (topic_option->retain_handling > 2 || topic_option->topic_filter.body == NULL) {
			debug_msg("ERROR: error in retain_handling");
			topic_node_t->it->reason_code = UNSPECIFIED_ERROR;
			return PROTOCOL_ERROR;
		}
		bpos ++;
		// TODO sub action when retain_handling equal 0 or 1 or 2

#if SUPPORT_MQTT5_0
		if (MQTT_VERSION_V5 == proto_ver &&
		    strncmp(topic_option->topic_filter.body, "$share/", strlen("$share/")) == 0 &&
		    topic_option->no_local == 1) {
			topic_node_t->it->reason_code = UNSPECIFIED_ERROR;
			return PROTOCOL_ERROR;
		}
#endif

next:
		debug_msg("bpos+vpos: [%d]", bpos + vpos);
		if (bpos < remaining_len - vpos) {
			if ((topic_node_t = nng_zalloc(sizeof(topic_node))) ==
			    NULL) {
				debug_msg("ERROR: nng_zalloc");
				return NNG_ENOMEM;
			}
			topic_node_t->next = NULL;
			_topic_node->next  = topic_node_t;
		} else {
			break;
		}
	}
	return 0;
}

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
	topic_node *node;

	packet_subscribe *sub_pkt;
	if ((sub_pkt = work->sub_pkt) == NULL)
		return (-1);

	const uint8_t proto_ver = work->proto_ver;

	// handle variable header first
	NNI_PUT16(packet_id, sub_pkt->packet_id);
	if ((rv = nng_msg_append(msg, packet_id, 2)) != 0) {
		debug_msg("ERROR: nng_msg_append [%d]", rv);
		return PROTOCOL_ERROR;
	}

#if SUPPORT_MQTT5_0
	if (PROTOCOL_VERSION_v5 == proto_ver) { // add property in variable
		encode_properties(msg, NULL, CMD_SUBACK);
	}
#endif

	// Note. packetid should be non-zero, BUT in order to make subclients
	// known that, we return an error(ALREADY IN USE)
	reason_code = PACKET_IDENTIFIER_IN_USE;
	if (sub_pkt->packet_id == 0) {
		if ((rv = nng_msg_append(msg, &reason_code, 1)) != 0) {
			debug_msg("ERROR: nng_msg_append [%d]", rv);
			return PROTOCOL_ERROR;
		}
	}

	// Note. When packet_id is zero, node must be empty. So, Dont worry
	// the order of reasone codes would be changed.
	// handle payload
	node = sub_pkt->node;
	while (node) {
		reason_code = node->it->reason_code;
		// MQTT_v3: 0x00-qos0  0x01-qos1  0x02-qos2  0x80-fail
		if ((rv = nng_msg_append(msg, &reason_code, 1)) != 0) {
			debug_msg("ERROR: nng_msg_append [%d]", rv);
			return PROTOCOL_ERROR;
		}
		node = node->next;
		debug_msg("reason_code: [%x]", reason_code);
	}

	// If NOT find any reason codes
	if (!sub_pkt->node && sub_pkt->packet_id != 0) {
		reason_code = UNSPECIFIED_ERROR;
		if ((rv = nng_msg_append(msg, &reason_code, 1)) != 0) {
			debug_msg("ERROR: nng_msg_append [%d]", rv);
			return PROTOCOL_ERROR;
		}
	}

	// handle fixed header
	cmd = CMD_SUBACK;
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

	debug_msg("remain: [%d] "
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
	topic_node *        tn = work->sub_pkt->node;
	char *              topic_str    = NULL;
	char *              clientid     = NULL;
	int                 topic_len    = 0;
	struct topic_queue *tq           = NULL;
	struct topic_queue *tq1          = NULL;
	int      topic_exist             = 0;
	uint32_t clientid_key            = 0;
	dbtree_retain_msg **r            = NULL;

	client_ctx * old_ctx    = NULL;
	dbtree_ctxt * db_ctxt 	= NULL;

	if (work->sub_pkt->packet_id == 0) {
		return PROTOCOL_ERROR;
	}

	client_ctx * cli_ctx = NULL;
	if ((cli_ctx = nng_zalloc(sizeof(client_ctx))) == NULL) {
		debug_msg("ERROR: nng_zalloc");
		return NNG_ENOMEM;
	}
	cli_ctx->sub_pkt        = work->sub_pkt;
	cli_ctx->cparam         = work->cparam;
	cli_ctx->pid            = work->pid;
	cli_ctx->proto_ver      = work->proto_ver;

	clientid = (char *) conn_param_get_clientid(
	    (conn_param *) nng_msg_get_conn_param(work->msg));
	if (clientid) {
		clientid_key = DJBHashn(clientid, strlen(clientid));
	}

	// get ctx from tree TODO optimization here
	tq = dbhash_get_topic_queue(cli_ctx->pid.id);

	if (tq) {
		db_ctxt = dbtree_find_client(
		    work->db, tq->topic, cli_ctx->pid.id);
	}
	tq1 = tq;

	if (db_ctxt) {
		old_ctx = db_ctxt->ctx;
	}

	if (!tq || !old_ctx) { /* the real ctx stored in tree */
		if ((old_ctx = nng_zalloc(sizeof(client_ctx))) == NULL){
			debug_msg("ERROR: nng_zalloc");
			return NNG_ENOMEM;
		}
		if ((old_ctx->sub_pkt = nng_zalloc(sizeof(packet_subscribe))) == NULL) {
			debug_msg("ERROR: nng_zalloc");
			return NNG_ENOMEM;
		}
		old_ctx->sub_pkt->node = NULL;
		old_ctx->cparam        = NULL;
#ifdef STATISTICS
		nng_atomic_alloc64(&old_ctx->recv_cnt);
#endif
	}
	/* Swap pid, capram, proto_ver in ctxs */
	old_ctx->pid.id    = cli_ctx->pid.id;
	old_ctx->proto_ver = cli_ctx->proto_ver;
	conn_param *cp     = old_ctx->cparam;
	old_ctx->cparam    = cli_ctx->cparam;
	cli_ctx->cparam    = cp;

	// clean session handle.
	debug_msg("clean session handle");
	cli_ctx_merge(cli_ctx, old_ctx);
	destroy_sub_ctx(cli_ctx);

	while (tn) {
		topic_len = tn->it->topic_filter.len;
		topic_str = tn->it->topic_filter.body;
		debug_msg("topicLen: [%d] body: [%s]", topic_len, topic_str);

		/* remove duplicate items */
		topic_exist = 0;
		tq          = dbhash_get_topic_queue(work->pid.id);
		while (topic_str && tq) {
			if (!strcmp(topic_str, tq->topic)) {
				topic_exist = 1;
				break;
			}
			tq = tq->next;
		}
		if (!topic_exist && topic_str) {
			uint8_t ver = work->proto_ver;
			dbtree_insert_client(
			    work->db, topic_str, old_ctx, work->pid.id, ver);

			dbhash_insert_topic(work->pid.id, topic_str);
		}
		// Note.
		// if topic already exists then update sub options.
		// qos, retain handling, no local (did in cli_ctx_merge)

		uint8_t rh = tn->it->retain_handling;
		if (topic_str)
			if (rh == 0 || (rh == 1 && !topic_exist))
				r = dbtree_find_retain(work->db_ret, topic_str);
		if (r) {
			for (int i = 0; i < cvector_size(r); i++) {
				if (!r[i])
					continue;
				cvector_push_back(
				    work->msg_ret, (nng_msg *) r[i]->message);
			}
		}
		cvector_free(r);

		tn = tn->next;
	}

	if (db_ctxt && 0 == dbtree_ctxt_free(db_ctxt)) {
		client_ctx *ctx = dbtree_ctxt_delete(db_ctxt);
		if (ctx) {
			del_sub_ctx(ctx, tq1->topic);
		}
	}
	

#ifdef DEBUG
	// check treeDB
	dbtree_print(work->db);
#endif
	debug_msg("end of sub ctx handle. \n");
	return 0;
}

static void
cli_ctx_merge(client_ctx *ctx_new, client_ctx *ctx)
{
	int                is_find = 0;
	struct topic_node *node, *node_new, *node_prev = NULL;
	struct topic_node *node_a = NULL;
	topic_with_option *two    = NULL;
	char *             str    = NULL;
	if (ctx->pid.id != ctx_new->pid.id) {
		return;
	}

#ifdef DEBUG /* Remove after testing */
	debug_msg("stored ctx:");
	node = ctx->sub_pkt->node;
	while (node) {
		debug_msg("%s", node->it->topic_filter.body);
		node = node->next;
	}
	debug_msg("new ctx");
	node_new = ctx_new->sub_pkt->node;
	while (node_new) {
		debug_msg("%s", node_new->it->topic_filter.body);
		node_new = node_new->next;
	}
#endif

	node_new = ctx_new->sub_pkt->node;
	while (node_new) {
		node      = ctx->sub_pkt->node;
		node_prev = NULL;
		is_find   = 0;
		//TODO optimize logic here with (FOREACH)
		while (node) {
			if (node_new->it->topic_filter.body != NULL)
			if (strcmp(node->it->topic_filter.body,
			        node_new->it->topic_filter.body) == 0) {
				is_find = 1;
				break;
			}
			node_prev = node;
			node      = node->next;
		}
		if (is_find) {
			// update option
			node->it->no_local = node_new->it->no_local;
			node->it->qos      = node_new->it->qos;
			node->it->rap      = node_new->it->rap;
			node->it->retain_handling =
			    node_new->it->retain_handling;
		} else { /* not find */
			// copy and append TODO optimize topic_node structure
			if (node_new->it->topic_filter.len < 1 ||
			    node_new->it->topic_filter.body == NULL) {
				debug_msg("next topic ");
				node_new = node_new->next;
				continue;
			}

			if (((node_a = nng_zalloc(sizeof(topic_node))) ==
			        NULL) ||
			    ((two = nng_zalloc(sizeof(topic_with_option))) ==
			        NULL) ||
			    ((str = nng_zalloc(node_new->it->topic_filter.len +
			          1)) == NULL)) {
				debug_msg("ERROR: nng_zalloc");
				return;
			}

			memcpy(two, node_new->it, sizeof(topic_with_option));
			strcpy(str, node_new->it->topic_filter.body);
			str[node_new->it->topic_filter.len] = '\0';
			node_a->it                          = two;
			two->topic_filter.body              = str;
			node_a->next                        = NULL;
			if (!node_prev) {
				ctx->sub_pkt->node = node_a;
			} else {
				node_prev->next = node_a;
			}
		}
		node_new = node_new->next;
	}

#ifdef DEBUG /* Remove after testing */
	debug_msg("after change.");
	debug_msg("stored ctx:");
	node = ctx->sub_pkt->node;
	while (node) {
		debug_msg("%s", node->it->topic_filter.body);
		node = node->next;
	}
	debug_msg("new ctx");
	node_new = ctx_new->sub_pkt->node;
	while (node_new) {
		debug_msg("%s", node_new->it->topic_filter.body);
		node_new = node_new->next;
	}
#endif
}

void
del_sub_ctx(void *ctxt, char *target_topic)
{
	client_ctx *      cli_ctx           = ctxt;
	topic_node *      topic_node_t      = NULL;
	topic_node *      before_topic_node = NULL;
	packet_subscribe *sub_pkt           = NULL;

	if (!cli_ctx || !cli_ctx->sub_pkt) {
		debug_msg("ERROR : ctx or sub_pkt is null!");
		return;
	}

	sub_pkt           = cli_ctx->sub_pkt;
	topic_node_t      = sub_pkt->node;
	before_topic_node = NULL;

	while (topic_node_t) {
		if (!strcmp(
		        topic_node_t->it->topic_filter.body, target_topic)) {
			debug_msg("FREE in topic_node [%s] in tree",
			    topic_node_t->it->topic_filter.body);
			if (before_topic_node) {
				before_topic_node->next = topic_node_t->next;
			} else {
				sub_pkt->node = topic_node_t->next;
			}

			nng_free(topic_node_t->it->topic_filter.body,
			    topic_node_t->it->topic_filter.len);
			nng_free(topic_node_t->it, sizeof(topic_with_option));
			nng_free(topic_node_t, sizeof(topic_node));
			break;
		}
		before_topic_node = topic_node_t;
		topic_node_t      = topic_node_t->next;
	}

	uint8_t proto_ver = cli_ctx->proto_ver;

	if (sub_pkt->node == NULL) {
#if SUPPORT_MQTT5_0
		if (PROTOCOL_VERSION_v5 == proto_ver) {
			if (sub_pkt->prop_len > 0) {
				property_free(sub_pkt->properties);
				sub_pkt->prop_len = 0;
			}
		}
#endif
		nng_free(sub_pkt, sizeof(packet_subscribe));
		nng_atomic_free64(cli_ctx->recv_cnt);
		nng_free(cli_ctx, sizeof(client_ctx));
		cli_ctx = NULL;
	}
}

void
destroy_sub_pkt(packet_subscribe *sub_pkt, uint8_t proto_ver)
{
	topic_node *topic_node_t, *next_topic_node;
	if (!sub_pkt) {
		return;
	}
	topic_node_t    = sub_pkt->node;
	next_topic_node = NULL;
	while (topic_node_t) {
		next_topic_node = topic_node_t->next;
		nng_free(topic_node_t->it->topic_filter.body,
		    topic_node_t->it->topic_filter.len);
		nng_free(topic_node_t->it, sizeof(topic_with_option));
		nng_free(topic_node_t, sizeof(topic_node));
		topic_node_t = next_topic_node;
	}

	if (sub_pkt) {
#if SUPPORT_MQTT5_0
		// what if there are multiple UPs?
		if (PROTOCOL_VERSION_v5 == proto_ver) {
			if (sub_pkt->prop_len > 0) {
				property_free(sub_pkt->properties);
				sub_pkt->prop_len = 0;
			}
		}
#endif
	}
	if (sub_pkt) {
		nng_free(sub_pkt, sizeof(packet_subscribe));
		sub_pkt = NULL;
	}
}

void
destroy_sub_ctx(void *ctxt)
{
	client_ctx *cli_ctx = ctxt;

	if (!cli_ctx) {
		debug_msg("ERROR : ctx or sub_pkt is null!");
		return;
	}
	nng_free(cli_ctx, sizeof(client_ctx));
}

void
destroy_sub_client(uint32_t pid, dbtree * db)
{
	dbtree_ctxt * db_ctxt = NULL;
	client_ctx * cli_ctx = NULL;
	topic_queue *tq = dbhash_get_topic_queue(pid);
	char *topic = tq->topic;

	while (tq) {
		if (tq->topic) {
			// Free from dbtree
			db_ctxt = dbtree_delete_client(db, topic, 0, pid);
			if (0 == dbtree_ctxt_free(db_ctxt)) {
				cli_ctx = dbtree_ctxt_delete(db_ctxt);
				if (cli_ctx) {
					del_sub_ctx(cli_ctx, tq->topic);
				}
				// dbhash_del_topic(pid, tq->topic);

			}

		}
		tq = tq->next;
	}

	// Free from dbhash
	dbhash_del_topic_queue(pid);

	return;
}

