// Copyright 2020 NanoMQ Team, Inc. <jaylin@emqx.io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//
#include <nanolib.h>
#include <nng.h>
#include <protocol/mqtt/mqtt.h>
#include <protocol/mqtt/mqtt_parser.h>

#include "include/nanomq.h"
#include "include/pub_handler.h"
#include "include/sub_handler.h"

#define SUPPORT_MQTT5_0 1

static void cli_ctx_merge(client_ctx *ctx, client_ctx *ctx_new);

void
init_sub_property(packet_subscribe *sub_pkt)
{
	sub_pkt->sub_id.varint                 = 0;
	sub_pkt->user_property.strpair.len_key = 0;
	sub_pkt->user_property.strpair.len_val = 0;
}

uint8_t
decode_sub_message(nano_work *work)
{
	uint8_t *variable_ptr;
	uint8_t *payload_ptr;
	int      vpos = 0; // pos in variable
	int      bpos = 0; // pos in payload

	size_t   len_of_varint = 0, len_of_property = 0, len_of_properties = 0;
	uint32_t len_of_str, len_of_topic;
	nng_msg *msg           = work->msg;
	size_t   remaining_len = nng_msg_remaining_len(msg);

	const uint8_t proto_ver = conn_param_get_protover(work->cparam);
	uint8_t       property_id;

	topic_node *       topic_node_t, *_topic_node;
	topic_with_option *topic_option;

	// handle variable header
	variable_ptr = nng_msg_body(msg);

	packet_subscribe *sub_pkt = work->sub_pkt;
	NNI_GET16(variable_ptr + vpos, sub_pkt->packet_id);
	vpos += 2;

#if SUPPORT_MQTT5_0
	// Only Mqtt_v5 include property.
	int target_pos;
	if (PROTOCOL_VERSION_v5 == proto_ver) {
		init_sub_property(sub_pkt);
		// length of property in varibale
		len_of_properties = get_var_integer(
		    variable_ptr + vpos, (uint32_t *) &len_of_varint);
		vpos += len_of_varint;
		len_of_varint = 0;
		target_pos    = vpos + len_of_properties;

		// parse property in variable
		if (len_of_properties > 0) {
			while (1) {
				property_id = variable_ptr[vpos++];
				switch (property_id) {
				case SUBSCRIPTION_IDENTIFIER:
					sub_pkt->sub_id.varint =
					    get_var_integer(
					        variable_ptr + vpos,
					        (uint32_t *) &len_of_varint);
					vpos += len_of_varint;
					break;
				case USER_PROPERTY:
					// key
					sub_pkt->user_property.strpair.key =
					    copy_utf8_str(variable_ptr, &vpos,
					        &len_of_str);
					sub_pkt->user_property.strpair
					    .len_key = len_of_str;
					len_of_str   = 0;

					// value
					sub_pkt->user_property.strpair.val =
					    copy_utf8_str(variable_ptr, &vpos,
					        &len_of_str);
					sub_pkt->user_property.strpair
					    .len_val = len_of_str;
					len_of_str   = 0;

					break;
				default:
					break;
				}
				if (vpos == target_pos)
					break;
				if (vpos > target_pos) {
					debug_msg("ERROR: protocol error");
					return PROTOCOL_ERROR;
				}
			}
		}
	}
#endif

	debug_msg("remainLen: [%ld] packetid : [%d]", remaining_len,
	    sub_pkt->packet_id);
	// handle payload
	payload_ptr = nng_msg_payload_ptr(msg);

	if ((topic_node_t = nng_alloc(sizeof(topic_node))) == NULL) {
		debug_msg("ERROR: nng_alloc");
		return NNG_ENOMEM;
	}
	topic_node_t->next = NULL;
	sub_pkt->node      = topic_node_t;

	while (1) {
		if ((topic_option = nng_alloc(sizeof(topic_with_option))) ==
		    NULL) {
			debug_msg("ERROR: nng_alloc");
			return NNG_ENOMEM;
		}
		topic_node_t->it = topic_option;
		_topic_node      = topic_node_t;

		topic_option->topic_filter.body =
		    copy_utf8_str(payload_ptr, &bpos, &len_of_topic);
		topic_option->topic_filter.len = len_of_topic;
		if (len_of_topic == 0) {
			debug_msg("ERROR : topic length error.");
			return PROTOCOL_ERROR;
		}
		len_of_topic = 0;

		memcpy(topic_option, payload_ptr + bpos, 1);
		// if (topic_option->retain_handling > 2) {
		// 	debug_msg("ERROR: error in retain_handling");
		// 	return PROTOCOL_ERROR;
		// }
		// TODO sub action when retain_handling equal 0 or 1 or 2

		debug_msg("bpos+vpos: [%d]", bpos + vpos);
		if (++bpos < remaining_len - vpos) {
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
encode_suback_message(nng_msg *msg, nano_work *work)
{
	nng_msg_clear(msg);

	uint8_t     packet_id[2];
	uint8_t     varint[4];
	uint8_t     reason_code, cmd;
	uint32_t    remaining_len, len_of_properties;
	int         len_of_varint, rv;
	topic_node *node;

	packet_subscribe *sub_pkt   = work->sub_pkt;
	const uint8_t     proto_ver = conn_param_get_protover(work->cparam);

	// handle variable header first
	NNI_PUT16(packet_id, sub_pkt->packet_id);
	if ((rv = nng_msg_append(msg, packet_id, 2)) != 0) {
		debug_msg("ERROR: nng_msg_append [%d]", rv);
		return PROTOCOL_ERROR;
	}

#if SUPPORT_MQTT5_0
	if (PROTOCOL_VERSION_v5 == proto_ver) { // add property in variable
		// 31(0x1f)ReasonCode - utf-8 string
		// 38(0x26)UserProperty - string pair
		len_of_varint =
		    put_var_integer(varint, 0); // len_of_properties = 0
		debug_msg("length of property [%d] [%x %x]", len_of_varint,
		    varint[0], varint[1]);
		if ((rv = nng_msg_append(msg, varint, len_of_varint)) != 0) {
			debug_msg("ERROR: nng_msg_append [%d]", rv);
			return PROTOCOL_ERROR;
		}
	}
#endif

	// handle payload
	node = sub_pkt->node;
	while (node) {
		if (node->it->reason_code == 0x80) {
			reason_code = 0x80;
		} else {
			reason_code = node->it->qos;
		}
		// MQTT_v3: 0x00-qos0  0x01-qos1  0x02-qos2  0x80-fail
		if ((rv = nng_msg_append(msg, (uint8_t *) &reason_code, 1)) !=
		    0) {
			debug_msg("ERROR: nng_msg_append [%d]", rv);
			return PROTOCOL_ERROR;
		}
		node = node->next;
		debug_msg("reason_code: [%x]", reason_code);
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

	debug_msg("remain: [%d]"
	          " varint: [%d %d %d %d]"
	          " len: [%d]"
	          " packetid: [%x %x]",
	    remaining_len, varint[0], varint[1], varint[2], varint[3],
	    len_of_varint, packet_id[0], packet_id[1]);

	return SUCCESS;
}

// generate ctx for each topic
uint8_t
sub_ctx_handle(nano_work *work)
{
	topic_node *        topic_node_t = work->sub_pkt->node;
	char *              topic_str    = NULL;
	char *              clientid     = NULL;
	int                 topic_len    = 0;
	struct topic_queue *tq           = NULL;
	work->msg_ret                    = NULL;
	int      topic_exist             = 0;
	uint32_t clientid_key            = 0;

	dbtree_ctxt *db_old_ctx = NULL;
	client_ctx * old_ctx    = NULL;
	client_ctx * cli_ctx    = nng_alloc(sizeof(client_ctx));
	cli_ctx->sub_pkt        = work->sub_pkt;
	cli_ctx->cparam         = work->cparam;
	cli_ctx->pid            = work->pid;
	cli_ctx->proto_ver      = conn_param_get_protover(work->cparam);

	clientid = (char *) conn_param_get_clientid(
	    (conn_param *) nng_msg_get_conn_param(work->msg));
	if (clientid) {
		clientid_key = DJBHashn(clientid, strlen(clientid));
	}

	// get ctx from tree TODO optimization here
	tq = dbhash_get_topic_queue(cli_ctx->pid.id);

	if (tq) {
		db_old_ctx = dbtree_delete_client(
		    work->db, tq->topic, clientid_key, cli_ctx->pid.id);
	}

	if (db_old_ctx) {
		old_ctx              = db_old_ctx->ctxt;
		db_old_ctx->sub_id_i = work->sub_pkt->sub_id.varint;
		dbtree_insert_client(
		    work->db, tq->topic, db_old_ctx, cli_ctx->pid.id);
	}

	if (!tq || !old_ctx) { /* the real ctx stored in tree */
		old_ctx                = nng_alloc(sizeof(client_ctx));
		old_ctx->sub_pkt       = nng_alloc(sizeof(packet_subscribe));
		old_ctx->sub_pkt->node = NULL;
		old_ctx->cparam        = NULL;
		init_sub_property(old_ctx->sub_pkt);
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

	while (topic_node_t) {
		topic_len = topic_node_t->it->topic_filter.len;
		topic_str = topic_node_t->it->topic_filter.body;
		debug_msg("topicLen: [%d] body: [%s]", topic_len, topic_str);

		/* remove duplicate items */
		topic_exist = 0;
		tq          = dbhash_get_topic_queue(work->pid.id);
		while (tq) {
			if (!strcmp(topic_str, tq->topic)) {
				topic_exist = 1;
				break;
			}
			tq = tq->next;
		}
		if (!topic_exist) {
			// printf("Protocol Version: %d\n",
			// old_ctx->proto_ver); printf("sub ID: %d\n",
			// work->sub_pkt->sub_id.varint);
			int          t = work->sub_pkt->sub_id.varint;
			dbtree_ctxt *db_old_ctxt = dbtree_new_ctxt(old_ctx, t);
			dbtree_insert_client(
			    work->db, topic_str, db_old_ctxt, work->pid.id);

			dbhash_insert_topic(work->pid.id, topic_str);
		}

		dbtree_retain_msg **r =
		    dbtree_find_retain(work->db_ret, topic_str);
		if (r) {
			for (int i = 0; i < cvector_size(r); i++) {
				if (!r[i]) {
					continue;
				}
				cvector_push_back(
				    work->msg_ret, (nng_msg *) r[i]->message);
			}
		}
		cvector_free(r);

		topic_node_t = topic_node_t->next;
	}

#ifdef DEBUG
	// check treeDB
	dbtree_print(work->db);
#endif
	debug_msg("end of sub ctx handle. \n");
	return SUCCESS;
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

#if SUPPORT_MQTT5_0
	if (ctx_new->sub_pkt->user_property.strpair.len_key) {
		ctx->sub_pkt->user_property.strpair.len_key =
		    ctx_new->sub_pkt->user_property.strpair.len_key;
		ctx->sub_pkt->user_property.strpair.key =
		    ctx_new->sub_pkt->user_property.strpair.key;
		ctx->sub_pkt->user_property.strpair.len_val =
		    ctx_new->sub_pkt->user_property.strpair.len_val;
		ctx->sub_pkt->user_property.strpair.val =
		    ctx_new->sub_pkt->user_property.strpair.val;
	}
	if (ctx_new->sub_pkt->sub_id.varint)
		ctx->sub_pkt->sub_id.varint = ctx_new->sub_pkt->sub_id.varint;
#endif

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
		while (node) {
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
			// node->it->retain_as_publish =
			//     node_new->it->retain_as_publish;
			// node->it->retain_handling =
			//     node_new->it->retain_handling;
		} else { /* not find */
			// copy and append TODO optimize topic_node structure
			node_a = nng_alloc(sizeof(topic_node));
			two    = nng_alloc(sizeof(topic_with_option));
			str    = nng_alloc(node_new->it->topic_filter.len + 1);
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
	uint8_t proto_ver = 0;

	client_ctx *      cli_ctx           = ctxt;
	topic_node *      topic_node_t      = NULL;
	topic_node *      before_topic_node = NULL;
	packet_subscribe *sub_pkt           = NULL;

	if (!cli_ctx || !cli_ctx->sub_pkt) {
		debug_msg("ERROR : ctx or sub_pkt is null!");
		return;
	}

	sub_pkt           = cli_ctx->sub_pkt;
	proto_ver         = cli_ctx->proto_ver;
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

	debug_msg("info: sub pkt node handling [%p]\n", sub_pkt->node);
	if (sub_pkt->node == NULL) {
#if SUPPORT_MQTT5_0
		if (PROTOCOL_VERSION_v5 == proto_ver) {
			if (sub_pkt->user_property.strpair.len_key > 0) {
				nng_free(
				    sub_pkt->user_property.strpair.key, 0);
				nng_free(
				    sub_pkt->user_property.strpair.val, 0);
			}
		}
#endif
		nng_free(sub_pkt, sizeof(packet_subscribe));
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
			if (sub_pkt->user_property.strpair.len_key > 0) {
				nng_free(sub_pkt->user_property.strpair.key,
				    sub_pkt->user_property.strpair.len_key);
				nng_free(sub_pkt->user_property.strpair.val,
				    sub_pkt->user_property.strpair.len_val);
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
	cli_ctx = NULL;
}

int
cache_session(char *clientid, conn_param *cparam, uint32_t pid, void *db)
{
	debug_msg("cache session");
	struct topic_queue *tq = NULL;

	uint32_t key_clientid = DJBHashn(clientid, strlen(clientid));

	if (dbhash_check_id(pid)) {
		tq = dbhash_get_topic_queue(pid);
		while (tq) {
			// TODO Is it necessary to get ctx and set pipeid to 0
			// in ctx ??
			dbtree_cache_session(db, tq->topic, key_clientid, pid);
			tq = tq->next;
		}
		dbhash_cache_topic_all(pid, key_clientid);
	}

	debug_msg("Session cached.");
	return 0;
}

int
restore_session(char *clientid, conn_param *cparam, uint32_t pid, void *db)
{
	debug_msg("restore session");
	client_ctx * ctx;
	topic_queue *tq = NULL;

	uint32_t key_clientid = DJBHashn(clientid, strlen(clientid));
	// TODO hash collision?
	// TODO kick prev connection(p or cs->pipeid)

	if (!dbhash_cached_check_id(key_clientid)) {
		return 0;
	}
	tq = dbhash_get_cached_topic(key_clientid);
	while (tq) {
		ctx = dbtree_restore_session(db, tq->topic, key_clientid, pid);
		tq  = tq->next;
	}
	if (ctx) {
		ctx->pid.id = pid;
	}

	dbhash_restore_topic_all(key_clientid, pid);
}
