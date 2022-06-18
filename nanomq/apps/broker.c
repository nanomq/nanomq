//
// Copyright 2022 NanoMQ Team, Inc. <jaylin@emqx.io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//
#include <ctype.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <conf.h>
#include <env.h>
#include <file.h>
#include <hash_table.h>
#include <mqtt_db.h>
#include <nng/mqtt/mqtt_client.h>
#include <nng/supplemental/tls/tls.h>
#include <nng/supplemental/util/options.h>
#include <nng/supplemental/util/platform.h>
#include <nng/supplemental/sqlite/sqlite3.h>
#include <nng/protocol/pipeline0/pull.h>
#include <nng/protocol/pipeline0/push.h>
#include <nng/protocol/mqtt/mqtt_parser.h>
#include <nng/protocol/mqtt/nmq_mqtt.h>
#include <zmalloc.h>

#include "include/bridge.h"
#include "include/mqtt_api.h"
#include "include/nanomq.h"
#include "include/process.h"
#include "include/pub_handler.h"
#include "include/sub_handler.h"
#include "include/unsub_handler.h"
#include "include/web_server.h"
#include "include/webhook_post.h"
#include "include/webhook_inproc.h"
#if defined(SUPP_RULE_ENGINE)
	#include <foundationdb/fdb_c.h>
	#include <foundationdb/fdb_c_options.g.h>
#endif

// Parallel is the maximum number of outstanding requests we can handle.
// This is *NOT* the number of threads in use, but instead represents
// outstanding work items.  Select a small number to reduce memory size.
// (Each one of these can be thought of as a request-reply loop.)  Note
// that you will probably run into limitations on the number of open file
// descriptors if you set this too high. (If not for that limit, this could
// be set in the thousands, each context consumes a couple of KB.)
#ifndef PARALLEL
#define PARALLEL 32
#endif

enum options {
	OPT_HELP = 1,
	OPT_CONFFILE,
	OPT_BRIDGEFILE,
	OPT_WEBHOOKFILE,
#if defined(SUPP_RULE_ENGINE)
	OPT_RULE_CONF,
#endif
	OPT_AUTHFILE,
	OPT_AUTH_HTTP_FILE,
	OPT_PARALLEL,
	OPT_DAEMON,
	OPT_THREADS,
	OPT_MAX_THREADS,
	OPT_PROPERTY_SIZE,
	OPT_MSQ_LEN,
	OPT_QOS_DURATION,
	OPT_URL,
	OPT_HTTP_ENABLE,
	OPT_HTTP_PORT,
	OPT_TLS_CA,
	OPT_TLS_CERT,
	OPT_TLS_KEY,
	OPT_TLS_KEYPASS,
	OPT_TLS_VERIFY_PEER,
	OPT_TLS_FAIL_IF_NO_PEER_CERT
};

static nng_optspec cmd_opts[] = {
	{ .o_name = "help", .o_short = 'h', .o_val = OPT_HELP },
	{ .o_name = "conf", .o_val = OPT_CONFFILE, .o_arg = true },
	{ .o_name = "bridge", .o_val = OPT_BRIDGEFILE, .o_arg = true },

#if defined(SUPP_RULE_ENGINE)
	{ .o_name = "rule", .o_val = OPT_RULE_CONF, .o_arg = true },
#endif
	{ .o_name = "webhook", .o_val = OPT_WEBHOOKFILE, .o_arg = true },
	{ .o_name = "auth", .o_val = OPT_AUTHFILE, .o_arg = true },
	{ .o_name = "auth_http", .o_val = OPT_AUTH_HTTP_FILE, .o_arg = true },
	{ .o_name = "daemon", .o_short = 'd', .o_val = OPT_DAEMON },
	{ .o_name    = "tq_thread",
	    .o_short = 't',
	    .o_val   = OPT_THREADS,
	    .o_arg   = true },
	{ .o_name    = "max_tq_thread",
	    .o_short = 'T',
	    .o_val   = OPT_MAX_THREADS,
	    .o_arg   = true },
	{ .o_name    = "parallel",
	    .o_short = 'n',
	    .o_val   = OPT_PARALLEL,
	    .o_arg   = true },
	{ .o_name    = "property_size",
	    .o_short = 's',
	    .o_val   = OPT_PROPERTY_SIZE,
	    .o_arg   = true },
	{ .o_name    = "msq_len",
	    .o_short = 'S',
	    .o_val   = OPT_MSQ_LEN,
	    .o_arg   = true },
	{ .o_name    = "qos_duration",
	    .o_short = 'D',
	    .o_val   = OPT_QOS_DURATION,
	    .o_arg   = true },
	{ .o_name = "url", .o_val = OPT_URL, .o_arg = true },
	{ .o_name = "http", .o_val = OPT_HTTP_ENABLE },
	{ .o_name    = "port",
	    .o_short = 'p',
	    .o_val   = OPT_HTTP_PORT,
	    .o_arg   = true },
	{ .o_name = "cacert", .o_val = OPT_TLS_CA, .o_arg = true },
	{ .o_name    = "cert",
	    .o_short = 'E',
	    .o_val   = OPT_TLS_CERT,
	    .o_arg   = true },
	{ .o_name = "key", .o_val = OPT_TLS_KEY, .o_arg = true },
	{ .o_name = "keypass", .o_val = OPT_TLS_KEYPASS, .o_arg = true },
	{ .o_name = "verify", .o_val = OPT_TLS_VERIFY_PEER },
	{ .o_name = "fail", .o_val = OPT_TLS_FAIL_IF_NO_PEER_CERT },
	{ .o_name = NULL, .o_val = 0 },
};

// The server keeps a list of work items, sorted by expiration time,
// so that we can use this to set the timeout to the correct value for
// use in poll.

#if (defined DEBUG) && (defined ASAN)
int keepRunning = 1;
void
intHandler(int dummy)
{
	
	keepRunning = 0;
	fprintf(stderr, "\nBroker exit(0).\n");
}
#endif

void
fatal(const char *func, int rv)
{
	fprintf(stderr, "%s: %s\n", func, nng_strerror(rv));
	exit(1);
}

void
server_cb(void *arg)
{
	nano_work *work = arg;
	nng_msg   *msg  = NULL;
	nng_msg   *smsg = NULL;
	int        rv;

	uint8_t *ptr;
	uint8_t  type;

	mqtt_msg_info *msg_info;

	switch (work->state) {
	case INIT:
		debug_msg("INIT ^^^^ ctx%d ^^^^\n", work->ctx.id);
		if (work->proto == PROTO_MQTT_BRIDGE) {
			work->state = BRIDGE;
			nng_ctx_recv(work->bridge_ctx, work->aio);
		} else {
			work->state = RECV;
			nng_ctx_recv(work->ctx, work->aio);
		}
		break;
	case RECV:
		debug_msg("RECV  ^^^^ ctx%d ^^^^\n", work->ctx.id);
		if ((rv = nng_aio_result(work->aio)) != 0) {
			debug_msg("ERROR: RECV nng aio result error: %d", rv);
		}
		if ((msg = nng_aio_get_msg(work->aio)) == NULL)
			fatal("RECV NULL MSG", rv);

		work->msg       = msg;
		work->pid       = nng_msg_get_pipe(work->msg);
		type = nng_msg_cmd_type(msg);
		if (type == CMD_DISCONNECT) {
			// TODO delete will msg if any
			work->cparam = nng_msg_get_conn_param(work->msg);
			if (work->cparam) {
				smsg = conn_param_get_will_msg(work->cparam);
				nng_msg_free(smsg);
			}
			work->state = RECV;
			nng_ctx_recv(work->ctx, work->aio);
			break;
		}
		work->cparam    = nng_msg_get_conn_param(work->msg);
		work->proto_ver = conn_param_get_protover(work->cparam);

		if (type == CMD_SUBSCRIBE) {
			smsg = work->msg;

			work->pid = nng_msg_get_pipe(work->msg);
			work->msg_ret = NULL;

			if ((work->sub_pkt = nng_alloc(
			         sizeof(packet_subscribe))) == NULL)
				debug_msg("ERROR: nng_alloc");
			memset(work->sub_pkt, '\0', sizeof(packet_subscribe));

			if ((rv = decode_sub_msg(work)) != 0 ||
			    (rv = sub_ctx_handle(work)) != 0) {
				work->code = rv;
				debug_msg("ERROR: sub_handler: [%d]", rv);
			}

			// TODO not all codes should close the pipe
			if (work->code != SUCCESS) {
				if (work->msg_ret)
					cvector_free(work->msg_ret);
				if (work->sub_pkt)
					destroy_sub_pkt(work->sub_pkt, work->proto_ver);
				// free conn_param due to clone in protocol layer
				conn_param_free(work->cparam);

				work->state = CLOSE;
				nng_aio_finish(work->aio, 0);
				return;
			}

			// TODO Error handling
			if (0 != (rv = encode_suback_msg(smsg, work)))
				debug_msg("error in encode suback: [%d]", rv);

			destroy_sub_pkt(work->sub_pkt, work->proto_ver);
			// handle retain (Retain flag handled in npipe)
			work->msg = NULL;
			if (work->msg_ret) {
				debug_msg("retain msg [%p] size [%ld] \n",
				    work->msg_ret,
				    cvector_size(work->msg_ret));
				for (int i = 0;
				     i < cvector_size(work->msg_ret) &&
				     check_msg_exp(work->msg_ret[i],
				         nng_msg_get_proto_data(
				             work->msg_ret[i]));
				     i++) {
					nng_msg *m = work->msg_ret[i];
					nng_msg_clone(m);
					work->msg = m;
					nng_aio_set_msg(work->aio, work->msg);
					nng_msg_set_pipe(work->msg, work->pid);
					nng_ctx_send(work->ctx, work->aio);
				}
				cvector_free(work->msg_ret);
			}
			nng_msg_set_cmd_type(smsg, CMD_SUBACK);
			nng_msg_set_pipe(smsg, work->pid);
			nng_aio_set_msg(work->aio, smsg);
			smsg = NULL;
			work->state = SEND;
			nng_ctx_send(work->ctx, work->aio);
			nng_aio_finish(work->aio, 0);
			// free conn_param due to clone in protocol layer
			conn_param_free(work->cparam);
			break;
		} else if (type == CMD_UNSUBSCRIBE) {
			work->pid = nng_msg_get_pipe(work->msg);
			smsg = work->msg;
			if ((work->unsub_pkt = nng_alloc(
			         sizeof(packet_unsubscribe))) == NULL)
				debug_msg("ERROR: nng_alloc");

			if ((rv = decode_unsub_msg(work)) != 0 ||
			    (rv = unsub_ctx_handle(work)) != 0) {
				debug_msg("ERROR: unsub_handler [%d]", rv);
			}

			if (0 != (rv = encode_unsuback_msg(smsg, work)))
				debug_msg("error in unsuback [%d]", rv);

			// free unsub_pkt
			destroy_unsub_ctx(work->unsub_pkt);

			work->pid.id = 0;
			nng_msg_set_pipe(work->msg, work->pid);
			nng_aio_set_msg(work->aio, work->msg);
			work->msg   = NULL;
			work->state = SEND;
			nng_ctx_send(work->ctx, work->aio);
			smsg = NULL;
			nng_aio_finish(work->aio, 0);
			break;
		} else if (type == CMD_PUBLISH) {
			// Set V4/V5 flag for publish msg
			if (work->proto_ver == 5) {
				nng_msg_set_cmd_type(msg, CMD_PUBLISH_V5);
			} else {
				nng_msg_set_cmd_type(msg, CMD_PUBLISH);
			}
			work->code = handle_pub(work, work->pipe_ct, work->proto_ver);
			if (work->code != SUCCESS) {
				work->state = CLOSE;
				free_pub_packet(work->pub_packet);
				cvector_free(work->pipe_ct->msg_infos);
				// free conn_param due to clone in protocol layer
				conn_param_free(work->cparam);
				nng_aio_finish(work->aio, 0);
				return;
			}

			// TODO move bridge after WAIT
			conf_bridge *bridge = &(work->config->bridge);
			if (bridge->bridge_mode) {
				bool found = false;
				for (size_t i = 0; i < bridge->forwards_count;
				     i++) {
					if (topic_filter(bridge->forwards[i],
					        work->pub_packet->var_header
					            .publish.topic_name
					            .body)) {
						found = true;
						break;
					}
				}

				if (found) {
					smsg = bridge_publish_msg(
					    work->pub_packet->var_header
					        .publish.topic_name.body,
					    work->pub_packet->payload.data,
					    work->pub_packet->payload.len,
					    work->pub_packet->fixed_header.dup,
					    work->pub_packet->fixed_header.qos,
					    work->pub_packet->fixed_header
					        .retain);
					work->state = WAIT;
					nng_aio_set_msg(
					    work->bridge_aio, smsg);
					//TODO check aio's cb
					nng_ctx_send(work->bridge_ctx,
					    work->bridge_aio);
				}
			}
		} else if (type == CMD_CONNACK) {
			nng_msg_set_pipe(work->msg, work->pid);
			// clone for sending connect event notification
			nng_msg_clone(work->msg);
			nng_aio_set_msg(work->aio, work->msg);
			nng_ctx_send(work->ctx, work->aio); // send connack

			uint8_t *body        = nng_msg_body(work->msg);
			uint8_t  reason_code = *(body + 1);
			smsg =
			    nano_msg_notify_connect(work->cparam, reason_code);
			webhook_client_connack(&work->webhook_sock,
			    &work->config->web_hook, work->proto_ver,
			    conn_param_get_keepalive(work->cparam),
			    reason_code, conn_param_get_username(work->cparam),
			    conn_param_get_clientid(work->cparam));
			// Set V4/V5 flag for publish notify msg
			nng_msg_set_cmd_type(smsg, CMD_PUBLISH);
			nng_msg_free(work->msg);
			work->msg = smsg;
			handle_pub(work, work->pipe_ct, PROTOCOL_VERSION_v311);
			// remember to free conn_param in WAIT 
			// due to clone in protocol layer
		} else if (type == CMD_DISCONNECT_EV) {
			// v4 as default, or send V5 notify msg?
			nng_msg_set_cmd_type(msg, CMD_PUBLISH);
			handle_pub(work, work->pipe_ct, PROTOCOL_VERSION_v311);
			// TODO set reason code if proto_version = MQTT_V5
			webhook_client_disconnect(&work->webhook_sock,
			    &work->config->web_hook,
			    conn_param_get_protover(work->cparam),
			    conn_param_get_keepalive(work->cparam), 0,
			    conn_param_get_username(work->cparam),
			    conn_param_get_clientid(work->cparam));
			// free client ctx
			if (dbhash_check_id(work->pid.id)) {
				destroy_sub_client(work->pid.id, work->db);
			} else {
				debug_msg("ERROR it should not happen");
			}
			if (conn_param_get_will_flag(work->cparam) == 0 ||
			    !conn_param_get_will_topic(work->cparam) ||
			    !conn_param_get_will_msg(work->cparam)) {
				// no will msg - free the cp
				conn_param_free(work->cparam);
			} else {
				// set to END tosend will msg
				work->state = END;
				// leave cp for will msg
				nng_aio_finish(work->aio, 0);
				break;
			}
		}
		work->state = WAIT;
		nng_aio_finish(work->aio, 0);
		break;
	case WAIT:
		// do not access to cparam
		debug_msg("WAIT ^^^^ ctx%d ^^^^", work->ctx.id);
		if (nng_msg_get_type(work->msg) == CMD_PUBLISH) {
			if ((rv = nng_aio_result(work->aio)) != 0) {
				debug_msg("WAIT nng aio result error: %d", rv);
				fatal("WAIT nng_ctx_recv/send", rv);
			}
			smsg      = work->msg; // reuse the same msg
			work->msg = NULL;

			cvector(mqtt_msg_info) msg_infos;
			msg_infos = work->pipe_ct->msg_infos;

			debug_msg("total pipes: %ld", cvector_size(msg_infos));
			if (cvector_size(msg_infos))
				if (encode_pub_message(smsg, work, PUBLISH))
					for (int i = 0; i < cvector_size(msg_infos) && rv== 0; ++i) {
						msg_info = &msg_infos[i];
						nng_msg_clone(smsg);
						work->pid.id = msg_info->pipe;
						nng_msg_set_pipe(smsg, work->pid);
						work->msg = NANO_NNI_LMQ_PACKED_MSG_QOS(smsg, msg_info->qos);
						nng_aio_set_msg(work->aio, work->msg);
						nng_ctx_send(work->ctx, work->aio);
					}
			// webhook here
			webhook_msg_publish(&work->webhook_sock,
			    &work->config->web_hook, work->pub_packet,
			    (const char *) conn_param_get_username(
			        work->cparam),
			    (const char *) conn_param_get_clientid(
			        work->cparam));
			// no client to send & free msg
			if (smsg != NULL) {
				nng_msg_free(smsg);
				smsg = NULL;
			}
			// free conn_param due to clone in protocol layer
			conn_param_free(work->cparam);
			work->msg = NULL;
			free_pub_packet(work->pub_packet);
			if (cvector_size(msg_infos) > 0) {
				work->state = SEND;
				cvector_free(msg_infos);
				work->pipe_ct->msg_infos = NULL;
				init_pipe_content(work->pipe_ct);
				nng_aio_finish(work->aio, 0);
				break;
			}
			cvector_free(work->pipe_ct->msg_infos);
			work->pipe_ct->msg_infos = NULL;
			init_pipe_content(work->pipe_ct);
			if (work->proto == PROTO_MQTT_BRIDGE) {
				work->state = BRIDGE;
			} else {
				work->state = RECV;
			}
			nng_ctx_recv(work->ctx, work->aio);
		} else if (nng_msg_cmd_type(work->msg) == CMD_PUBACK ||
		    nng_msg_cmd_type(work->msg) == CMD_PUBREL ||
		    nng_msg_cmd_type(work->msg) == CMD_PUBCOMP) {
			nng_msg_free(work->msg);
			work->msg   = NULL;
			work->state = RECV;
			nng_ctx_recv(work->ctx, work->aio);
			break;
		} else if (nng_msg_cmd_type(work->msg) == CMD_PINGREQ) {
			smsg = work->msg;
			nng_msg_clear(smsg);
			ptr    = nng_msg_header(smsg);
			ptr[0] = CMD_PINGRESP;
			ptr[1] = 0x00;
			nng_msg_set_cmd_type(smsg, CMD_PINGRESP);
			work->msg = smsg;
			work->pid = nng_msg_get_pipe(work->msg);
			nng_msg_set_pipe(work->msg, work->pid);
			nng_aio_set_msg(work->aio, work->msg);
			work->msg   = NULL;
			work->state = SEND;
			nng_ctx_send(work->ctx, work->aio);
			smsg = NULL;
			nng_aio_finish(work->aio, 0);
		} else if (nng_msg_cmd_type(work->msg) == CMD_PUBREC) {
			smsg   = work->msg;
			ptr    = nng_msg_header(smsg);
			ptr[0] = 0x62;
			ptr[1] = 0x02;
			nng_msg_set_cmd_type(smsg, CMD_PUBREL);
			work->msg = smsg;
			work->pid = nng_msg_get_pipe(work->msg);
			nng_msg_set_pipe(work->msg, work->pid);
			nng_aio_set_msg(work->aio, work->msg);
			work->msg   = NULL;
			work->state = SEND;
			nng_ctx_send(work->ctx, work->aio);
			smsg = NULL;
			nng_aio_finish(work->aio, 0);
		} else {
			debug_msg("broker has nothing to do");
			if (work->msg != NULL)
				nng_msg_free(work->msg);
			work->msg   = NULL;
			work->state = RECV;
			nng_ctx_recv(work->ctx, work->aio);
			break;
		}
		break;
	case BRIDGE:
		if ((rv = nng_aio_result(work->aio)) != 0) {
			debug_msg("nng_recv_aio: %s", nng_strerror(rv));
			work->state = RECV;
			nng_ctx_recv(work->bridge_ctx, work->aio);
			break;
		}
		work->msg = nng_aio_get_msg(work->aio);
		msg       = work->msg;

		nng_msg_set_cmd_type(msg, nng_msg_get_type(msg));
		work->msg   = msg;
		work->state = RECV;
		nng_aio_finish(work->aio, 0);
		break;
	case SEND:
		if (NULL != smsg) {
			smsg = NULL;
		}
		if ((rv = nng_aio_result(work->aio)) != 0) {
			fatal("SEND nng_ctx_send", rv);
		}
		if (work->pipe_ct->msg_infos) {
			free_pub_packet(work->pub_packet);
			cvector_free(work->pipe_ct->msg_infos);
			work->pipe_ct->msg_infos = NULL;
		}
		work->msg = NULL;
		if (work->proto == PROTO_MQTT_BRIDGE) {
			work->state = BRIDGE;
			nng_ctx_recv(work->bridge_ctx, work->aio);
		} else {
			work->state = RECV;
			nng_ctx_recv(work->ctx, work->aio);
		}
		break;
	case END:
		debug_msg("END ^^^^ ctx%d ^^^^", work->ctx.id);
		if (nng_msg_get_type(work->msg) == CMD_PUBLISH) {
			if ((rv = nng_aio_result(work->aio)) != 0) {
				debug_msg("WAIT nng aio result error: %d", rv);
				fatal("WAIT nng_ctx_recv/send", rv);
			}
			smsg      = work->msg; // reuse the same msg
			work->msg = NULL;

			cvector(mqtt_msg_info) msg_infos;
			msg_infos = work->pipe_ct->msg_infos;

			debug_msg("total pipes: %ld", cvector_size(msg_infos));
			//TODO encode abstract msg only
			if (cvector_size(msg_infos))
				if (encode_pub_message(smsg, work, PUBLISH))
					for (int i=0; i<cvector_size(msg_infos); ++i) {
						msg_info = &msg_infos[i];
						nng_msg_clone(smsg);
						work->pid.id = msg_info->pipe;
						nng_msg_set_pipe(smsg, work->pid);
						work->msg = NANO_NNI_LMQ_PACKED_MSG_QOS(smsg, msg_info->qos);
						nng_aio_set_msg(work->aio, work->msg);
						nng_ctx_send(work->ctx, work->aio);
					}
			nng_msg_free(smsg);
			smsg = NULL;
			work->msg = NULL;
			free_pub_packet(work->pub_packet);
			cvector_free(work->pipe_ct->msg_infos);
			work->pipe_ct->msg_infos = NULL;
			init_pipe_content(work->pipe_ct);

			// processing will msg
			if (conn_param_get_will_flag(work->cparam)) {
				msg = nano_pubmsg_composer(&msg,
				    conn_param_get_will_retain(work->cparam),
				    conn_param_get_will_qos(work->cparam),
				    (mqtt_string *) conn_param_get_will_msg(
				        work->cparam),
				    (mqtt_string *) conn_param_get_will_topic(
				        work->cparam),
				    conn_param_get_protover(work->cparam),
					nng_clock());
				work->msg = msg;
				// Set V4/V5 flag for publish msg
				if (conn_param_get_protover(work->cparam) == 5) {
					property *will_property =
					    conn_param_get_will_property(
					        work->cparam);
					nng_msg_set_cmd_type(
					    msg, CMD_PUBLISH_V5);
					handle_pub(work, work->pipe_ct,
					    PROTOCOL_VERSION_v5);
					work->pub_packet->var_header.publish
					    .properties = property_pub_by_will(will_property);
					work->pub_packet->var_header.publish
					    .prop_len = get_properties_len(
					    work->pub_packet->var_header
					        .publish.properties);
				} else {
					nng_msg_set_cmd_type(msg, CMD_PUBLISH);
					handle_pub(work, work->pipe_ct, PROTOCOL_VERSION_v311);
				}
				work->state = WAIT;
				nng_aio_finish(work->aio, 0);
			} else {
				if (work->msg != NULL)
					nng_msg_free(work->msg);
				work->msg = NULL;
				if (work->proto == PROTO_MQTT_BRIDGE) {
					work->state = BRIDGE;
				} else {
					work->state = RECV;
				}
				nng_ctx_recv(work->ctx, work->aio);
			}
		}
		conn_param_free(work->cparam);
		break;
	case CLOSE:
		debug_msg(" CLOSE ^^^^ ctx%d ^^^^", work->ctx.id);
		smsg = nano_dismsg_composer(work->code, NULL, NULL, NULL);
		nng_msg_free(work->msg);
		work->msg = smsg;
		// compose a disconnect msg
		nng_msg_set_pipe(work->msg, work->pid);
		// clone for sending connect event notification
		nng_aio_set_msg(work->aio, work->msg);
		nng_ctx_send(work->ctx, work->aio); // send connack

		// clear reason code
		work->code = SUCCESS;

		work->state = RECV;
		nng_ctx_recv(work->ctx, work->aio);
		break;
	default:
		fatal("bad state!", NNG_ESTATE);
		break;
	}
}

struct work *
alloc_work(nng_socket sock)
{
	struct work *w;
	int          rv;

	if ((w = nng_alloc(sizeof(*w))) == NULL) {
		fatal("nng_alloc", NNG_ENOMEM);
	}
	if ((rv = nng_aio_alloc(&w->aio, server_cb, w)) != 0) {
		fatal("nng_aio_alloc", rv);
	}
	if ((rv = nng_ctx_open(&w->ctx, sock)) != 0) {
		fatal("nng_ctx_open", rv);
	}

	w->pipe_ct = nng_alloc(sizeof(struct pipe_content));
	init_pipe_content(w->pipe_ct);

	w->state = INIT;
	return (w);
}

nano_work *
proto_work_init(nng_socket sock, nng_socket bridge_sock, uint8_t proto,
    dbtree *db_tree, dbtree *db_tree_ret, conf *config)
{
	int        rv;
	nano_work *w;
	w         = alloc_work(sock);
	w->db     = db_tree;
	w->db_ret = db_tree_ret;
	w->proto  = proto;
	w->config = config;
	w->code   = SUCCESS;

	if (config->bridge.bridge_mode) {
		if ((rv = nng_ctx_open(&w->bridge_ctx, bridge_sock)) != 0) {
			fatal("nng_ctx_open", rv);
		}
		if ((rv = nng_aio_alloc(&w->bridge_aio, NULL, NULL) != 0)) {
			fatal("nng_aio_alloc", rv);
		}
	}

	if(config->web_hook.enable) {
		if ((rv = nng_push0_open(&w->webhook_sock)) != 0) {
			fatal("nng_socket", rv);
		}
		if ((rv = nng_dial(w->webhook_sock, WEB_HOOK_INPROC_URL, NULL,
		         0)) != 0) {
			fatal("nng_dial", rv);
		}
	}

	return w;
}

static dbtree *db     = NULL;
static dbtree *db_ret = NULL;

dbtree *
get_broker_db(void)
{
	return db;
}

int
broker(conf *nanomq_conf)
{
	nng_socket sock;
	nng_socket bridge_sock;
	nng_pipe   pipe_id;
	int        rv;
	int        i;
	// add the num of other proto
	uint64_t num_ctx = nanomq_conf->parallel;

#if defined(SUPP_RULE_ENGINE)
	if (nanomq_conf->rule_engine_option) {
		switch (nanomq_conf->rule_engine_db_option) {
		case RULE_ENGINE_FDB:
			pthread_t   netThread;
			fdb_error_t err =
			    fdb_select_api_version(FDB_API_VERSION);
			if (err) {
				debug_msg("select API version error: %s",
				    fdb_get_error(err));
				exit(1);
			}
			FDBDatabase *fdb   = openDatabase(&netThread);
			nanomq_conf->rdb   = fdb;
			FDBTransaction *tr = NULL;
			fdb_error_t     e =
			    fdb_database_create_transaction(fdb, &tr);
			nanomq_conf->tran = tr;
			break;

		case RULE_ENGINE_SDB:
			sqlite3 *sdb;
			char    *sqlite_path =
                            nanomq_conf->rule_engine_sqlite_path
			       ? nanomq_conf->rule_engine_sqlite_path
			       : "rule_engine.db";
			int rc = sqlite3_open(
			    nanomq_conf->rule_engine_sqlite_path, &sdb);
			// puts(nanomq_conf->rule_engine_sqlite_path);
			if (rc != SQLITE_OK) {
				fprintf(stderr, "Cannot open database: %s\n",
				    sqlite3_errmsg(sdb));
				sqlite3_close(sdb);
				exit(1);
			}
			nanomq_conf->sdb = (void *) sdb;

			// char *compose_table(nanomq_conf);
			char         sqlite_table[1024];
			static char *key_arr[] = {
				"Qos",
				"Id",
				"Topic",
				"Clientid",
				"Username",
				"Password",
				"Timestamp",
				"Payload",
			};

			static char *type_arr[] = {
				" INT",
				" INT",
				" TEXT",
				" TEXT",
				" TEXT",
				" TEXT",
				" INT",
				" TEXT",
			};
			// "CREATE TABLE Broker(Qos INT, Id INT
			rule_engine_info info  = nanomq_conf->rule_engine[0];
			int              index = 0;
			char             table[512] =
			    "CREATE TABLE IF NOT EXISTS Broker("
			    "RowId INTEGER PRIMARY KEY AUTOINCREMENT";

			char *err_msg   = NULL;
			bool  first     = true;

			for (; index < 8; index++) {
				if (!info.flag[index])
					continue;

				strcat(table, ", ");
				strcat(table,
				    info.as[index] ? info.as[index]
				                   : key_arr[index]);
				strcat(table, type_arr[index]);
			}
			strcat(table, ");");
			// puts(table);
			rc = sqlite3_exec(sdb, table, 0, 0, &err_msg);
			if (rc != SQLITE_OK) {
				fprintf(stderr, "SQL error: %s\n", err_msg);

				sqlite3_free(err_msg);
				sqlite3_close(sdb);

				return 1;
			}

			break;

		default:
			break;
		}
	}

#endif

	// init tree
	dbtree_create(&db);
	if (db == NULL) {
		debug_msg("NNL_ERROR error in db create");
	}
	dbtree_create(&db_ret);
	if (db_ret == NULL) {
		debug_msg("NNL_ERROR error in db create");
	}

	dbhash_init_cached_table();
	dbhash_init_pipe_table();
	dbhash_init_alias_table();

	/*  Create the socket. */
	nanomq_conf->db_root = db;
	sock.id              = 0;
	sock.data            = nanomq_conf;
	rv                   = nng_nmq_tcp0_open(&sock);
	if (rv != 0) {
		fatal("nng_nmq_tcp0_open", rv);
	}

	if (nanomq_conf->bridge.bridge_mode) {
		num_ctx += nanomq_conf->bridge.parallel;
		bridge_client(&bridge_sock, nanomq_conf);
	}

	struct work *works[num_ctx];

	for (i = 0; i < nanomq_conf->parallel; i++) {
		works[i] = proto_work_init(sock, bridge_sock,
		    PROTO_MQTT_BROKER, db, db_ret, nanomq_conf);
	}

	if (nanomq_conf->bridge.bridge_mode) {
		for (i = nanomq_conf->parallel; i < num_ctx; i++) {
			works[i] = proto_work_init(sock, bridge_sock,
			    PROTO_MQTT_BRIDGE, db, db_ret, nanomq_conf);
		}
	}

	if ((rv = nano_listen(sock, nanomq_conf->url, NULL, 0, nanomq_conf)) != 0) {
		fatal("nng_listen", rv);
	}

	// read from command line & config file
	if (nanomq_conf->websocket.enable) {
		if ((rv = nano_listen(
		         sock, nanomq_conf->websocket.url, NULL, 0, nanomq_conf)) != 0) {
			fatal("nng_listen ws", rv);
		}
	}

	if (nanomq_conf->tls.enable) {
		nng_listener tls_listener;

		if ((rv = nng_listener_create(
		         &tls_listener, sock, nanomq_conf->tls.url)) != 0) {
			fatal("nng_listener_create tls", rv);
		}
		nng_listener_set(
		    tls_listener, NANO_CONF, nanomq_conf, sizeof(nanomq_conf));

		init_listener_tls(tls_listener, &nanomq_conf->tls);
		if ((rv = nng_listener_start(tls_listener, 0)) != 0) {
			fatal("nng_listener_start tls", rv);
		}
		// TODO websocket ssl 
		// if (nanomq_conf->websocket.enable) {
		// 	nng_listener wss_listener;
		// 	if ((rv = nng_listener_create(&wss_listener, sock,
		// 	         nanomq_conf->tls.url)) != 0) {
		// 		fatal("nng_listener_create wss", rv);
		// 	}
		// 	init_listener_tls(wss_listener, &nanomq_conf->tls);
		// 	if ((rv = nng_listener_start(wss_listener, 0)) != 0) {
		// 		fatal("nng_listener_start wss", rv);
		// 	}
		// }
	}

	for (i = 0; i < num_ctx; i++) {
		server_cb(works[i]); // this starts them going (INIT state)
	}

#if (defined DEBUG) && (defined ASAN)
	signal(SIGINT, intHandler);
	for (;;) {
		if (keepRunning == 0) {
#if defined(SUPP_RULE_ENGINE)
			fdb_transaction_destroy(nanomq_conf->tran);
			fdb_database_destroy(nanomq_conf->rdb);
			fdb_stop_network();
#endif
			exit(0);
		}
		nng_msleep(6000);
	}
#else
	for (;;) {
		nng_msleep(3600000); // neither pause() nor sleep() portable
	}
#endif
}

void
print_usage(void)
{
	printf("Usage: nanomq broker { { start | restart [--url <url>] "
	       "[--conf <path>] "
	       "[--bridge <path>] \n                     "
	       "[--webhook <path>] "
		   "[--auth <path>] "
		   "[--auth_http <path>] "
	       "[-d, --daemon] \n                     "
	       "[-t, --tq_thread <num>] "
	       "[-T, -max_tq_thread <num>] [-n, "
	       "--parallel <num>]\n                     "
	       "[-D, --qos_duration <num>] [--http] "
	       "[-p, --port] } \n                     "
	       "[--cacert <path>] [-E, --cert <path>] [--key <path>] \n       "
	       "        "
	       "      [--keypass <password>] [--verify] [--fail]\n            "
	       "         "
	       "| stop }\n\n");

	printf("Options: \n");
	printf("  --url <url>                Specify listener's url: "
	       "'nmq-tcp://host:port', 'tls+nmq-tcp://host:port' \n"
	       "                             or 'nmq-ws://host:port/path' or "
	       "'nmq-wss://host:port/path'\n");
	printf("  --conf <path>              The path of a specified nanomq "
	       "configuration file \n");

#if defined(SUPP_RULE_ENGINE)
	printf("  --rule <path>              The path of a specified rule "
	       "configuration file \n");
#endif
	printf("  --bridge <path>            The path of a specified bridge "
	       "configuration file \n");
	printf("  --webhook <path>           The path of a specified webhook "
	       "configuration file \n");
	printf(
	    "  --auth <path>              The path of a specified authorize "
	    "configuration file \n");
	printf("  --auth_http <path>         The path of a specified http "
	       "authorize "
	       "configuration file \n");
	printf("  --http                     Enable http server (default: "
	       "false)\n");
	printf(
	    "  -p, --port <num>           The port of http server (default: "
	    "8081)\n");
	printf(
	    "  -t, --tq_thread <num>      The number of taskq threads used, "
	    "`num` greater than 0 and less than 256\n");
	printf(
	    "  -T, --max_tq_thread <num>  The maximum number of taskq threads "
	    "used, `num` greater than 0 and less than 256\n");
	printf(
	    "  -n, --parallel <num>       The maximum number of outstanding "
	    "requests we can handle\n");
	printf("  -s, --property_size <num>  The max size for a MQTT user "
	       "property\n");
	printf("  -S, --msq_len <num>        The queue length for resending "
	       "messages\n");
	printf("  -D, --qos_duration <num>   The interval of the qos timer\n");
	printf("  -d, --daemon               Run nanomq as daemon (default: "
	       "false)\n");
	printf("  --cacert                   Path to the file containing "
	       "PEM-encoded CA certificates\n");
	printf("  -E, --cert                 Path to a file containing the "
	       "user certificate\n");
	printf("  --key                      Path to the file containing the "
	       "user's private PEM-encoded key\n");
	printf("  --keypass                  String containing the user's "
	       "password. Only used if the private keyfile is "
	       "password-protected\n");
	printf("  --verify                   Set verify peer "
	       "certificate (default: false)\n");
	printf("  --fail                     Server will fail if the client "
	       "does not have a certificate to send (default: false)\n");
}

int
status_check(pid_t *pid)
{
#ifdef NANO_PLATFORM_WINDOWS
	debug_msg("Not support on Windows\n");
	return -1;
#else
	char  *data = NULL;
	size_t size = 0;

	int rc;
	if ((rc = nng_file_get(PID_PATH_NAME, (void *) &data, &size)) != 0) {
		nng_free(data, size);
		debug_msg(".pid file not found or unreadable\n");
		return 1;
	} else {
		if ((data) != NULL) {
			sscanf(data, "%u", pid);
			debug_msg("pid read, [%u]", *pid);
			nng_free(data, size);

			if ((kill(*pid, 0)) == 0) {
				debug_msg("there is a running NanoMQ instance "
				          ": pid [%u]",
				    *pid);
				return 0;
			}
		}
		if (!nng_file_delete(PID_PATH_NAME)) {
			debug_msg(".pid file is removed");
			return 1;
		}
		debug_msg("unexpected error");
		return -1;
	}
#endif
}

int
store_pid()
{
	int  status;
	char pid_c[12] = "";

	sprintf(pid_c, "%d", getpid());
	debug_msg("%s", pid_c);

	status = nng_file_put(PID_PATH_NAME, pid_c, sizeof(pid_c));
	return status;
}

void
active_conf(conf *nanomq_conf)
{
	// check if daemonlize
	if (nanomq_conf->daemon == true && process_daemonize()) {
		fprintf(stderr, "Error occurs, cannot daemonize\n");
		exit(EXIT_FAILURE);
	}
	// taskq and max_taskq
	if (nanomq_conf->num_taskq_thread || nanomq_conf->max_taskq_thread) {
		nng_taskq_setter(nanomq_conf->num_taskq_thread,
		    nanomq_conf->max_taskq_thread);
	}
}

static void
predicate_url(conf *config, char *url)
{
	if (strncmp(BROKER_NMQ_TCP_URL_PREFIX, url,
	        strlen(BROKER_NMQ_TCP_URL_PREFIX)) == 0 ||
	    strncmp(BROKER_TCP_URL_PREFIX, url,
	        strlen(BROKER_TCP_URL_PREFIX)) == 0) {
		FREE_NONULL(config->url);
		config->url = nng_strdup(url);
	}
	if (strncmp(BROKER_NMQ_TCP_TLS_URL_PREFIX, url,
	        strlen(BROKER_NMQ_TCP_TLS_URL_PREFIX)) == 0) {
		FREE_NONULL(config->tls.url);
		config->tls.enable = true;
		config->tls.url    = nng_strdup(url);
	} else if (strncmp(BROKER_NMQ_WS_URL_PREFIX, url,
	               strlen(BROKER_NMQ_WS_URL_PREFIX)) == 0 ||
	    strncmp(BROKER_WS_URL_PREFIX, url, strlen(BROKER_WS_URL_PREFIX)) ==
	        0) {
		if (strncmp(BROKER_NMQ_WSS_URL_PREFIX, url,
		        strlen(BROKER_NMQ_WSS_URL_PREFIX)) == 0 ||
		    strncmp(BROKER_WSS_URL_PREFIX, url,
		        strlen(BROKER_WSS_URL_PREFIX)) == 0) {
			FREE_NONULL(config->websocket.tls_url);
			config->tls.enable        = true;
			config->websocket.tls_url = nng_strdup(url);
		} else {
			FREE_NONULL(config->websocket.url);
			config->websocket.url = nng_strdup(url);
		}
		config->websocket.enable = true;
	}
}

int
broker_parse_opts(int argc, char **argv, conf *config)
{
	int   idx = 0;
	char *arg;
	int   val;
	int   rv;

	while ((rv = nng_opts_parse(argc, argv, cmd_opts, &val, &arg, &idx)) ==
	    0) {
		switch (val) {
		case OPT_HELP:
			print_usage();
			exit(0);
			break;
		case OPT_CONFFILE:
			FREE_NONULL(config->conf_file);
			config->conf_file = nng_strdup(arg);
			break;
		case OPT_BRIDGEFILE:
			FREE_NONULL(config->bridge_file);
			config->bridge_file = nng_strdup(arg);
			break;
		case OPT_WEBHOOKFILE:
			FREE_NONULL(config->web_hook_file);
			config->web_hook_file = nng_strdup(arg);
			break;

#if defined(SUPP_RULE_ENGINE)
		case OPT_RULE_CONF:
			FREE_NONULL(config->rule_engine_file);
			config->rule_engine_file = nng_strdup(arg);
			break;
#endif
		case OPT_AUTHFILE:
			FREE_NONULL(config->auth_file);
			config->auth_file = nng_strdup(arg);
			break;
		case OPT_AUTH_HTTP_FILE:
			FREE_NONULL(config->auth_http_file);
			config->auth_http_file = nng_strdup(arg);
			break;
		case OPT_PARALLEL:
			config->parallel = atoi(arg);
			break;
		case OPT_DAEMON:
			config->daemon = true;
			break;
		case OPT_THREADS:
			config->num_taskq_thread = atoi(arg);
			break;
		case OPT_MAX_THREADS:
			config->max_taskq_thread = atoi(arg);
			break;
		case OPT_PROPERTY_SIZE:
			config->property_size = atoi(arg);
			break;
		case OPT_MSQ_LEN:
			config->msq_len = atoi(arg);
			break;
		case OPT_QOS_DURATION:
			config->qos_duration = atoi(arg);
			break;
		case OPT_URL:
			predicate_url(config, arg);
			break;
		case OPT_TLS_CA:
			FREE_NONULL(config->tls.ca);
			file_load_data(arg, (void **) &config->tls.ca);
			break;
		case OPT_TLS_CERT:
			FREE_NONULL(config->tls.cert);
			file_load_data(arg, (void **) &config->tls.cert);
			break;
		case OPT_TLS_KEY:
			FREE_NONULL(config->tls.key);
			file_load_data(arg, (void **) &config->tls.key);
			break;
		case OPT_TLS_KEYPASS:
			FREE_NONULL(config->tls.key_password);
			config->tls.key_password = nng_strdup(arg);
			break;
		case OPT_TLS_VERIFY_PEER:
			config->tls.verify_peer = true;
			break;
		case OPT_TLS_FAIL_IF_NO_PEER_CERT:
			config->tls.set_fail = true;
			break;
		case OPT_HTTP_ENABLE:
			config->http_server.enable = true;
			break;
		case OPT_HTTP_PORT:
			config->http_server.port = atoi(arg);
			break;

		default:
			break;
		}
	}

	switch (rv) {
	case NNG_EINVAL:
		fprintf(stderr,
		    "Option %s is invalid.\nTry 'nanomq broker --help' for "
		    "more information.\n",
		    argv[idx]);
		break;
	case NNG_EAMBIGUOUS:
		fprintf(stderr,
		    "Option %s is ambiguous (specify in full).\nTry 'nanomq "
		    "broker --help' for more information.\n",
		    argv[idx]);
		break;
	case NNG_ENOARG:
		fprintf(stderr,
		    "Option %s requires argument.\nTry 'nanomq broker --help' "
		    "for more information.\n",
		    argv[idx]);
		break;
	default:
		break;
	}

	return rv == -1;
}

int
broker_start(int argc, char **argv)
{
	int   i, url, temp, rc, num_ctx = 0;
	pid_t pid              = 0;
	char *conf_path        = NULL;
	char *bridge_conf_path = NULL;
	conf *nanomq_conf;

	if (!status_check(&pid)) {
		fprintf(stderr,
		    "One NanoMQ instance is still running, a new instance "
		    "won't be started until the other one is stopped.\n");
		exit(EXIT_FAILURE);
	}

	if ((nanomq_conf = nng_zalloc(sizeof(conf))) == NULL) {
		fprintf(stderr,
		    "Cannot allocate storge for configuration, quit\n");
		exit(EXIT_FAILURE);
	}

	nanomq_conf->parallel = PARALLEL;

	// Priority: config < environment variables < command opts


	conf_init(nanomq_conf);
	conf_parser(nanomq_conf);
	conf_bridge_parse(nanomq_conf);
	read_env_conf(nanomq_conf);

	if (!broker_parse_opts(argc, argv, nanomq_conf)) {
		conf_fini(nanomq_conf);
		return -1;
	}

	if (nanomq_conf->conf_file) {
		conf_parser(nanomq_conf);
	}
	if (nanomq_conf->bridge_file) {
		conf_bridge_parse(nanomq_conf);
	}

#if defined(SUPP_RULE_ENGINE)
	if (nanomq_conf->rule_engine_file) {
		conf_rule_engine_parse(nanomq_conf);
	}
#endif


	if (nanomq_conf->web_hook_file) {
		conf_web_hook_parse(nanomq_conf);
	}

	nanomq_conf->url = nanomq_conf->url != NULL
	    ? nanomq_conf->url
	    : nng_strdup(CONF_TCP_URL_DEFAULT);

	if (nanomq_conf->tls.enable) {
		nanomq_conf->tls.url = nanomq_conf->tls.url != NULL
		    ? nanomq_conf->tls.url
		    : nng_strdup(CONF_TLS_URL_DEFAULT);
	}

	if (nanomq_conf->websocket.enable) {
		nanomq_conf->websocket.url = nanomq_conf->websocket.url != NULL
		    ? nanomq_conf->websocket.url
		    : nng_strdup(CONF_WS_URL_DEFAULT);

		if (nanomq_conf->tls.enable) {
			nanomq_conf->websocket.tls_url =
			    nanomq_conf->websocket.tls_url != NULL
			    ? nanomq_conf->websocket.tls_url
			    : nng_strdup(CONF_WSS_URL_DEFAULT);
		}
	}

	print_conf(nanomq_conf);
	print_bridge_conf(&nanomq_conf->bridge);

	active_conf(nanomq_conf);

	if (nanomq_conf->web_hook.enable) {
		start_webhook_service(nanomq_conf);
	}

	if (nanomq_conf->http_server.enable) {
		start_rest_server(nanomq_conf);
	}

	if (store_pid()) {
		debug_msg("create \"nanomq.pid\" file failed");
	}

	rc = broker(nanomq_conf);

	if(nanomq_conf->web_hook.enable) {
		stop_webhook_service();
	}

	if (nanomq_conf->http_server.enable) {
		stop_rest_server();
	}
	exit(rc == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
}

#ifndef NANO_PLATFORM_WINDOWS

int
broker_stop(int argc, char **argv)
{
	pid_t pid = 0;

	if (argc != 0) {
		print_usage();
		exit(EXIT_FAILURE);
	}

	if (!(status_check(&pid))) {
		kill(pid, SIGTERM);
	} else {
		fprintf(stderr, "There is no running NanoMQ instance.\n");
		exit(EXIT_FAILURE);
	}
	fprintf(stderr, "NanoMQ stopped.\n");
	exit(EXIT_SUCCESS);
}

int
broker_restart(int argc, char **argv)
{
	pid_t pid = 0;

	if (!(status_check(&pid))) {
		kill(pid, SIGTERM);
		while (!status_check(&pid)) {
			kill(pid, SIGKILL);
		}
		fprintf(stderr, "Previous NanoMQ instance stopped.\n");
	} else {
		fprintf(stderr, "There is no running NanoMQ instance.\n");
	}

	return broker_start(argc, argv);
}

#else

int
broker_restart(int argc, char **argv)
{
	fprintf(stderr, "Not support on Windows\n");
	exit(EXIT_SUCCESS);
}


int
broker_stop(int argc, char **argv)
{
	fprintf(stderr, "Not support on Windows\n");
	exit(EXIT_SUCCESS);
}

#endif

int
broker_dflt(int argc, char **argv)
{
	print_usage();
	return 0;
}
