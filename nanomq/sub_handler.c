//
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

// clean session
static void restore_topic_to_tree(void *tree, client_ctx *cli_ctx, char *client_id);
static void *del_topic_from_tree(void *tree, topic_queue *tq, uint32_t pid);

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
	if (PROTOCOL_VERSION_v5 == proto_ver) {
		init_sub_property(sub_pkt);
		// length of property in varibale
		len_of_properties = get_var_integer(
		    variable_ptr + vpos, (uint32_t *) &len_of_varint);
		vpos += len_of_varint;
		int target_pos = vpos + len_of_properties;

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
					NNI_GET16(
					    variable_ptr + vpos, len_of_str);
					if ((sub_pkt->user_property.strpair
					            .key = nng_alloc(
					         len_of_str)) == 0) {
						debug_msg("ERROR: nng_alloc");
						return NNG_ENOMEM;
					}
					sub_pkt->user_property.strpair
					    .len_key = len_of_str;
					vpos += (len_of_str + 2);
					len_of_str = 0;

					// value
					NNI_GET16(
					    variable_ptr + vpos, len_of_str);
					if ((sub_pkt->user_property.strpair
					            .val = nng_alloc(
					         len_of_str)) == 0) {
						debug_msg("ERROR: nng_alloc");
						return NNG_ENOMEM;
					}
					sub_pkt->user_property.strpair
					    .len_val = len_of_str;
					vpos += (len_of_str + 2);
					len_of_str = 0;

					break;
				default:
					break;
				}
				if (vpos >= target_pos) {
					break;
				} else if (vpos > target_pos) {
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

	debug_msg("V:[%x %x %x %x] P:[%x %x %x %x].", variable_ptr[0],
	    variable_ptr[1], variable_ptr[2], variable_ptr[3], payload_ptr[0],
	    payload_ptr[1], payload_ptr[2], payload_ptr[3]);

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

		NNI_GET16(payload_ptr + bpos, len_of_topic);
		bpos += 2;

		if (len_of_topic != 0) {
			topic_option->topic_filter.len = len_of_topic;
			topic_option->topic_filter.body =
			    nng_alloc(len_of_topic + 1);
			if (topic_option->topic_filter.body == NULL) {
				debug_msg("ERROR: nng_alloc");
				return NNG_ENOMEM;
			}
			strncpy(topic_option->topic_filter.body,
			    (char *) (payload_ptr + bpos), len_of_topic);
			topic_option->topic_filter.body[len_of_topic] = '\0';
			bpos += len_of_topic;
		} else {
			debug_msg("ERROR : topic length error.");
			return PROTOCOL_ERROR;
		}

		memcpy(topic_option, payload_ptr + bpos, 1);
		if (topic_option->retain_handling > 2) {
			debug_msg(
			    "ERROR: error inretain_handling flag setting");
			return PROTOCOL_ERROR;
		}
		// TODO sub action when retain_handling equal 0 or 1 or 2

		debug_msg("bpos+vpos: [%d] remainLen: [%ld].", bpos + vpos,
		    remaining_len);
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
		if (PROTOCOL_VERSION_v5 == proto_ver) {
		} else {
			if (node->it->reason_code == 0x80) {
				reason_code = 0x80;
			} else {
				reason_code = node->it->qos;
			}
			// MQTT_v3: 0x00-qos0  0x01-qos1  0x02-qos2  0x80-fail
			if ((rv = nng_msg_append(
			         msg, (uint8_t *) &reason_code, 1)) != 0) {
				debug_msg("ERROR: nng_msg_append [%d]", rv);
				return PROTOCOL_ERROR;
			}
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
	char *              client_id    = NULL;
	int                 topic_len    = 0;
	struct topic_queue *tq           = NULL;
	work->msg_ret                    = NULL;
	int topic_exist                  = 0;

	client_ctx *old_ctx = NULL;
	client_ctx *cli_ctx = nng_alloc(sizeof(client_ctx));
	cli_ctx->sub_pkt    = work->sub_pkt;
	cli_ctx->cparam     = work->cparam;
	cli_ctx->pid        = work->pid;
	cli_ctx->proto_ver  = conn_param_get_protover(work->cparam);

	client_id = (char *) conn_param_get_clientid(
	    (conn_param *) nng_msg_get_conn_param(work->msg));

	// get ctx from tree TODO optimization here
	tq = get_topic(cli_ctx->pid.id);
	if (tq) {
		old_ctx =
		    search_and_delete(work->db, tq->topic, cli_ctx->pid.id);
	}
	if (old_ctx) {
		search_and_insert(
		    work->db, tq->topic, client_id, old_ctx, cli_ctx->pid.id);
	}
	if (!tq || !old_ctx) { /* the real ctx stored in tree */
		old_ctx                = nng_alloc(sizeof(client_ctx));
		old_ctx->sub_pkt       = nng_alloc(sizeof(packet_subscribe));
		old_ctx->sub_pkt->node = NULL;
		old_ctx->cparam        = NULL;
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
		tq          = get_topic(work->pid.id);
		while (tq) {
			if (!strcmp(topic_str, tq->topic)) {
				topic_exist = 1;
				break;
			}
			tq = tq->next;
		}
		if (!topic_exist) {
			search_and_insert(work->db, topic_str, client_id,
			    old_ctx, work->pid.id);
			add_topic(work->pid.id, topic_str);
		}
#ifdef DEBUG
		// check
		debug_msg("--CHECK--cliid: [%s] pipeid: [%d]", client_id,
		    work->pid.id);
#endif

		retain_msg **r = search_retain(work->db_ret, topic_str);
		if (r) {
			for (int i = 0; i < cvector_size(r); i++) {
				if (!r[i]) {
					continue;
				}
				debug_msg("found retain [%p], "
				          "message: [%p][%p] sz [%d]\n",
				    r[i], r[i]->message,
				    nng_msg_payload_ptr(r[i]->message),
				    cvector_size(r));
				cvector_push_back(
				    work->msg_ret, (nng_msg *) r[i]->message);
			}
		}
		cvector_free(r);

		topic_node_t = topic_node_t->next;
	}

	// check treeDB
	print_db_tree(work->db);
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
			node->it->retain_as_publish =
			    node_new->it->retain_as_publish;
			node->it->retain_handling =
			    node_new->it->retain_handling;
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
	uint8_t           proto_ver         = 0;
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
			if (sub_pkt->user_property.strpair.len_key) {
				nng_free(sub_pkt->user_property.strpair.key,
				    sub_pkt->user_property.strpair.len_key);
				nng_free(sub_pkt->user_property.strpair.val,
				    sub_pkt->user_property.strpair.len_val);
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
		if (PROTOCOL_VERSION_v5 == proto_ver) {
			nng_free(sub_pkt->user_property.strpair.key,
			    sub_pkt->user_property.strpair.len_key);
			nng_free(sub_pkt->user_property.strpair.val,
			    sub_pkt->user_property.strpair.len_val);
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
cache_session(char * clientid, conn_param * cparam, uint32_t pid, void *db)
{
	debug_msg("cache session");
	client_ctx *        cli_ctx = NULL;
	struct topic_queue *tq      = NULL;
	nano_clean_session *cs      = NULL;

	void * nano_qos_db = conn_param_get_qos_db(cparam);
	uint32_t key_clientid = DJBHashn(clientid, strlen(clientid));

	// create cs if not exist
	if ((cs = get_session(key_clientid)) == NULL) {
		if ((cs = nng_alloc(sizeof(nano_clean_session))) == NULL) {
			return (ENOMEM);
		}
		debug_msg("create nano clean session");
	}
	add_session(key_clientid, cs);

	// deep copy connection parameter
	// TODO Do we needs using cparam? in clean session on MQTTV5
	conn_param_clone(cparam); // Make it not be freed when recv Disconnect EV

	cs->cparam = cparam;

	// step 1 move nano_qos_db to cs struct
	cs->msg_map = nano_qos_db;
	debug_msg("the nano_qos_db has an address: %p", nano_qos_db);

	// step 2-1 find clictx and kept it, but delete it from tree.
	// step 2-2 move topic from topic map to cached topic map
	// (hash.cc)
	if (check_id(pid)) {
		tq = get_topic(pid);
		if ((cli_ctx = del_topic_from_tree(db, tq, pid)) != NULL) {
			cli_ctx->pid.id = 0;
			cs->cltx   = cli_ctx;
		}
		cache_topic_all(pid, key_clientid);
		debug_msg("move");
	} else {
		debug_msg("(CS=0) UNEXPECTED: no stored topic queue, tq lost "
		          "or client may not subed topic");
	}
	// step 3 move nano_pipe_db to temp_cs struct (move pointer)
//	temp_cs->pipe_db = p->pipedb_root;
//	p->pipedb_root   = NULL;

	debug_msg("Session cached.");
	return 0;
}

int
restore_session(char * clientid, conn_param * cparam, uint32_t pid, void * db)
{
	debug_msg("restore session");
	conn_param * old_cparam;
	client_ctx * ctx;
	uint8_t      cs_flag = conn_param_get_clean_start(cparam);
	nano_clean_session *cs;

	uint32_t key_clientid = DJBHashn(clientid, strlen(clientid));
	// TODO hash collision?
	cs = (nano_clean_session *)get_session(key_clientid);

/*
	if (cs && cs->pipeid != 0) {
		// TODO kick prev connection(p or cs->pipeid)
		p->kicked = true;
		if (cparam->pro_ver == 5) {
			*(flag +1 ) = 0x8E;
		} else {
			*(flag +1 ) = 0x02;
		}
		return (NNG_ECONNABORTED);
	}
*/

	// no matter if client enabled cleansession. use clean-session-db for
	// duplicate clientid verifying.
	if (cs == NULL) {
		debug_msg("no cached ingo");
		// no cached info
		return 0;
	}

	void *        msgs       = cs->msg_map;
	nano_pipe_db *topics     = cs->pipe_db;
	nano_pipe_db *topic_node = topics;
	cs->pipeid               = pid;

	old_cparam     = cs->cparam;
	ctx            = cs->cltx;

	// step 0 restore conn param
//	deep_copy_conn_param(cparam, old_cparam);
	conn_param_free(old_cparam);

	// step 1 restore cli_ctx and cached_topic_queue
	if (ctx != NULL) {
		ctx->pid.id = pid;
	}
	if (cached_check_id(key_clientid)) {
		restore_topic_all(key_clientid, pid);
		restore_topic_to_tree(db, ctx, clientid);
	} else {
		debug_msg("(CS=0) UNEXPECTED: no stored cached topic queue");
	}

	// step 2 restore topic in pipe_db
//	p->pipedb_root = topics;
//	cs->pipe_db    = NULL;
	// step 3 restore nano_pipe_db<topic, pipe_db>
/*
	while (topic_node->next) {
		nni_id_set(&p->pipe->nano_db,DJBHashn(
		        topic_node->topic, strlen(topic_node->topic)), topic_node);
		topic_node = topic_node->next;
	}
*/
	// step 4 restore nano_qos_db
	// TODO new coming message may use the existing packet id in
	// one client nano_qos_db
	// TODO merge the msgs. Then publish them.
/*
	nni_id_map_fini(p->pipe->nano_qos_db);
	nng_free(p->pipe->nano_qos_db, sizeof(struct nni_id_map));
	p->pipe->nano_qos_db       = msgs;
*/
	conn_param_set_qos_db(cparam, msgs);

	debug_msg("Session restored finish");


	if (cs_flag == 0) { // not clean session
		cs->clean = false;
	} else {
		cs->clean = true;
		nng_free(cs, sizeof(nano_clean_session));
		del_session(key_clientid);
	}
	return 0;
}
/* duplicate with the codes in pipe_fini()
	} else { // clean session
		cs->clean = true;
		// step 0 remove conn param
		destroy_conn_param(cparam);
		cparam = NULL;
		// step 1 remove nano_qos_db
		nni_id_iterate(msgs, nni_id_msgfree_cb);
		nni_id_map_fini(msgs);
		nng_free(msgs, sizeof(struct nni_id_map));
		msgs = NULL;
		// step 2 delete 2-1 cli_ctx and cached topic queue
		if (cached_check_id(key)) {
			topic_queue *tq = get_cached_topic(key);
			while (tq) {
				del_sub_ctx(cltx, tq->topic);
				tq = tq->next;
			}
			del_cached_topic_all(key);
		} else {
			debug_msg(
			    "(CS=1) UNEXPECTED: no stored cached topic queue");
		}
		// step 3 delete topics in pipe_db
		nano_msg_free_pipedb(topics);
		debug_msg(
		    "(CS=1) All last session related information disgarded");
*/

static void
restore_topic_to_tree(void *tree, client_ctx *cli_ctx, char *client_id)
{
	topic_node *tn_t = cli_ctx->sub_pkt->node;

	while (tn_t) {
		debug_msg("Now adding topic (from last session), body: [%s]",
		    tn_t->it->topic_filter.body);
		search_and_insert(tree, tn_t->it->topic_filter.body, client_id,
		    cli_ctx, cli_ctx->pid.id);
		tn_t = tn_t->next;
	}
}

static void *
del_topic_from_tree(void *tree, topic_queue *tq, uint32_t pid)
{
	client_ctx *cli_ctx = NULL;

	while (tq) {
		if (tq->topic) {
			cli_ctx = search_and_delete(tree, tq->topic, pid);
		}
		debug_msg("delete pipe id [%d] topic: [%s]", pid, tq->topic);
		tq = tq->next;
	}

	return cli_ctx;
}

