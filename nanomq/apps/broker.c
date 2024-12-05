//
// Copyright 2023 NanoMQ Team, Inc. <jaylin@emqx.io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>

#include "nng/mqtt/mqtt_client.h"
#include "nng/exchange/exchange_client.h"
#include "nng/protocol/mqtt/nmq_mqtt.h"
#include "nng/protocol/pipeline0/pull.h"
#include "nng/protocol/pipeline0/push.h"
#include "nng/protocol/reqrep0/rep.h"
#include "nng/protocol/mqtt/mqtt_parser.h"
#include "nng/protocol/mqtt/nmq_mqtt.h"
#include "nng/supplemental/tls/tls.h"
#include "nng/supplemental/util/options.h"
#include "nng/supplemental/util/platform.h"
#include "nng/supplemental/sqlite/sqlite3.h"
#include "nng/supplemental/nanolib/conf.h"
#include "nng/supplemental/nanolib/env.h"
#include "nng/supplemental/nanolib/file.h"
#include "nng/supplemental/nanolib/hash_table.h"
#include "nng/supplemental/nanolib/mqtt_db.h"
#include "nng/supplemental/nanolib/log.h"
#include "nng/supplemental/nanolib/utils.h"

#include "include/acl_handler.h"
#include "include/bridge.h"
#include "include/nanomq_rule.h"
#include "include/mqtt_api.h"
#include "include/nanomq.h"
#include "include/process.h"
#include "include/pub_handler.h"
#include "include/sub_handler.h"
#include "include/unsub_handler.h"
#include "include/web_server.h"
#include "include/rest_api.h"
#include "include/webhook_post.h"
#include "include/webhook_inproc.h"
#include "include/cmd_proc.h"
#include "include/process.h"
#include "include/nanomq.h"

#if defined(SUPP_ICEORYX)
	#include "nng/iceoryx_shm/iceoryx_shm.h"
#endif

#if defined(SUPP_PLUGIN)
	#include "include/plugin.h"
#endif
// #if defined(SUPP_RULE_ENGINE)
// 	#include <foundationdb/fdb_c.h>
// 	#include <foundationdb/fdb_c_options.g.h>
// #endif
#if defined(SUPP_AWS_BRIDGE)
	#include "include/aws_bridge.h"
#endif
// Parallel is the maximum number of outstanding requests we can handle.
// This is *NOT* the number of threads in use, but instead represents
// outstanding work items.  Select a small number to reduce memory size.
// (Each one of these can be thought of as a request-reply loop.)  Note
// that you will probably run into limitations on the number of open file
// descriptors if you set this too high. (If not for that limit, this could
// be set in the thousands, each context consumes a couple of KB.) Recommend to
// set as the same as your CPU cores.

#if (defined DEBUG) && (defined ASAN)
int keepRunning = 1;
void
intHandler(int dummy)
{
	keepRunning = 0;
	fprintf(stderr, "\nBroker exit(0).\n");
}
#else
#if !defined(NANO_PLATFORM_WINDOWS)
static const int all_signals[] = {
#ifdef SIGHUP
	SIGHUP,
#endif
#ifdef SIGQUIT
	SIGQUIT,
#endif
#ifdef SIGTRAP
	SIGTRAP,
#endif
#ifdef SIGIO
	SIGIO,
#endif
	SIGABRT,
	SIGFPE,
	SIGILL,
	SIGINT,
	SIGSEGV,
	SIGTERM
};

void sig_handler(int signum)
{
	log_error("signal signumber: %d received!\n", signum);

	if (signum == SIGINT || signum == SIGABRT || signum == SIGSEGV) {
		exit(EXIT_FAILURE);
	}
	if (signum == SIGILL || signum == SIGTERM)
		exit(EXIT_SUCCESS);
}
#endif
#endif

enum options {
	OPT_HELP = 1,
	OPT_HOCONFILE = 2, /* Do not change this value, it is used beyond this file. */
	OPT_CONFFILE = 3,  /* Do not change this value, it is used beyond this file. */
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
	OPT_TLS_FAIL_IF_NO_PEER_CERT,
	OPT_LOG_LEVEL,
	OPT_LOG_STDOUT,
	OPT_LOG_FILE,
	OPT_LOG_SYSLOG,
};

static nng_optspec cmd_opts[] = {
	{ .o_name = "help", .o_short = 'h', .o_val = OPT_HELP },
	{ .o_name = "conf", .o_val = OPT_HOCONFILE, .o_arg = true },
	{ .o_name = "old_conf", .o_val = OPT_CONFFILE, .o_arg = true },
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
	{ .o_name = "log_level", .o_val = OPT_LOG_LEVEL, .o_arg = true },
	{ .o_name = "log_stdout", .o_val = OPT_LOG_STDOUT, .o_arg = true },
	{ .o_name = "log_syslog", .o_val = OPT_LOG_SYSLOG, .o_arg = true },
	{ .o_name = "log_file", .o_val = OPT_LOG_FILE, .o_arg = true },
	{ .o_name = NULL, .o_val = 0 },
};

// The server keeps a list of work items, sorted by expiration time,
// so that we can use this to set the timeout to the correct value for
// use in poll.

static inline void
bridge_pub_handler(nano_work *work)
{
	int      rv    = 0;
	property *props = NULL;
	uint32_t  index = work->ctx.id - 1;
	mqtt_string *topic;

	// Or we just exclude all topic with $?
	if ((work->pub_packet->var_header.publish.topic_name.len > strlen("$SYS")) &&
		strncmp(work->pub_packet->var_header.publish.topic_name.body, "$SYS", strlen("$SYS")) == 0) {
		return;
	}
	topic = nng_zalloc(sizeof(*topic));
	for (size_t t = 0; t < work->config->bridge.count; t++) {
		conf_bridge_node *node = work->config->bridge.nodes[t];
		nng_mtx_lock(node->mtx);		//TODO bridge performance
		if (node->enable) {
			for (size_t i = 0; i < node->forwards_count; i++) {
				rv = 0;
				topic->body = work->pub_packet->var_header.publish.topic_name.body;
				topic->len  = work->pub_packet->var_header.publish.topic_name.len;
				if (topic_filter(node->forwards_list[i]->local_topic,
							(const char *)topic->body)) {
					work->state = SEND;

					nng_msg *bridge_msg = NULL;
					if (work->proto_ver == MQTT_PROTOCOL_VERSION_v5 &&
						node->proto_ver == MQTT_PROTOCOL_VERSION_v5) {
						mqtt_property_dup(
						    &props, work->pub_packet->var_header.publish.properties);
					}
					// No change if remote topic == ""
					if (node->forwards_list[i]->remote_topic_len != 0) {
						topic->body = node->forwards_list[i]->remote_topic;
						topic->len = node->forwards_list[i]->remote_topic_len;
					}
					if (node->forwards_list[i]->prefix != NULL) {
						topic->body =
							nng_strnins(topic->body, node->forwards_list[i]->prefix,
										topic->len, node->forwards_list[i]->prefix_len);
						topic->len = strlen(topic->body);
						rv = NNG_STAT_STRING;	//mark it for free
					}
					if (node->forwards_list[i]->suffix != NULL) {
						char *tmp = topic->body;
						topic->body =
							nng_strncat(topic->body, node->forwards_list[i]->suffix,
										topic->len, node->forwards_list[i]->suffix_len);
						topic->len = strlen(topic->body);
						if (rv == NNG_STAT_STRING)
							nng_free(tmp, strlen(tmp));
						else
							rv = NNG_STAT_STRING;	//mark it for free
					}
					uint8_t retain;
					uint8_t qos;
					retain =
					    node->forwards_list[i]->retain == NO_RETAIN
					    ? work->pub_packet->fixed_header.retain
					    : node->forwards_list[i]->retain;
					qos    =
					    node->forwards_list[i]->qos == NO_QOS
					    ? work->pub_packet->fixed_header.qos
					    : node->forwards_list[i]->qos;
					bridge_msg = bridge_publish_msg(
					    topic->body,
					    work->pub_packet->payload.data,
					    work->pub_packet->payload.len,
					    work->pub_packet->fixed_header.dup,
					    qos, retain, props);
					if (rv == NNG_STAT_STRING) {
						nng_free(topic->body,strlen(topic->body));
					}

					node->proto_ver == MQTT_PROTOCOL_VERSION_v5
					    ? nng_mqttv5_msg_encode(bridge_msg)
					    : nng_mqtt_msg_encode(bridge_msg);

					nng_socket *socket = node->sock;

					// what if send qos msg failed?
					// nanosdk deal with fail send
					// and close the pipe
					if (nng_aio_busy(node->bridge_aio[index])) {
						if (nng_lmq_full(node->ctx_msgs) || qos == 0) {
							nng_msg_free(bridge_msg);
							log_warn(
								"bridging to %s aio busy! "
								"msg lost! Ctx: %d",
								node->address, work->ctx.id);
						} else {
							// pass index of aio via timestamp;
							nng_lmq_put(node->ctx_msgs, bridge_msg);
						}
					} else {
						nng_aio_set_timeout(node->bridge_aio[index],
											node->cancel_timeout);
						nng_aio_set_msg(node->bridge_aio[index], bridge_msg);
						// switch to nng_ctx_send!
						nng_send_aio(*socket, node->bridge_aio[index]);
					}
					rv = SUCCESS;
				}
			}
		}
		nng_mtx_unlock(node->mtx);
	}
	nng_free(topic, sizeof(topic));
	return;
}

void
server_cb(void *arg)
{
	nano_work     *work = arg;
	nng_msg       *msg  = NULL;
	nng_msg       *smsg = NULL;
	int            rv;

	mqtt_msg_info *msg_info;
	nng_socket    *newsock = NULL;

	switch (work->state) {
	case INIT:
		// log_debug("INIT ^^^^^^^^ ctx [%d] ^^^^^^^^ \n", work->ctx.id);
		work->state = RECV;
		if (work->proto == PROTO_MQTT_BROKER) {
			log_debug("INIT ^^^^^^^^ ctx [%d] ^^^^^^^^ \n", work->ctx.id);
			nng_ctx_recv(work->ctx, work->aio);
#if defined(SUPP_ICEORYX)
		} else if (work->proto == PROTO_ICEORYX_BRIDGE) {
			log_debug("INIT ^^^^^^^^ iceoryx ctx [%d] ^^^^^^^^ \n", work->extra_ctx.id);
			nng_aio_set_prov_data(work->aio, work->iceoryx_suber);
			nng_ctx_recv(work->extra_ctx, work->aio);
#endif
		} else {
			log_debug("INIT ^^^^^^^^ extra ctx [%d] ^^^^^^^^ \n", work->extra_ctx.id);
			nng_ctx_recv(work->extra_ctx, work->aio);
		}
		break;
	case RECV:
		log_debug("RECV  ^^^^ ctx%d ^^^^\n", work->ctx.id);
		msg = nng_aio_get_msg(work->aio);
		if ((rv = nng_aio_result(work->aio)) != 0) {
			log_info("RECV aio result: %d", rv);
			work->state = RECV;
			if (work->proto == PROTO_MQTT_BROKER) {
				if (msg != NULL)
					nng_msg_free(msg);
				nng_ctx_recv(work->ctx, work->aio);
				break;
			} else {
				// check notify msg of bridge
				if (rv != NNG_ECONNSHUT || msg == NULL) {
					nng_ctx_recv(work->extra_ctx, work->aio);
					break;
				}
				log_info("bridge connection closed with reason %d\n", rv);
			}
		}

		if (work->proto == PROTO_MQTT_BRIDGE) {
			uint8_t type = nng_msg_get_type(msg);
			if (type == CMD_CONNACK) {
				log_info("bridge client is connected!");
			} else if (type == CMD_PUBLISH) {
			} else {
				// only accept publish/CONNACK/DISCONNECT
				// msg from upstream
				work->state = RECV;
				nng_msg_free(msg);
				nng_ctx_recv(work->extra_ctx, work->aio);
				break;
			}
		} else if (work->proto == PROTO_HTTP_SERVER ||
		    work->proto == PROTO_AWS_BRIDGE) {
			nng_msg *decode_msg = NULL;
			if (decode_common_mqtt_msg(&decode_msg, msg) != 0 ||
			    nng_msg_get_type(decode_msg) != CMD_PUBLISH) {
				conn_param_free(nng_msg_get_conn_param(decode_msg));
				work->state = RECV;
				nng_ctx_recv(work->extra_ctx, work->aio);
				break;
			}
			msg = decode_msg;
			nng_msg_set_cmd_type(msg, CMD_PUBLISH);
			// alloc conn_param every single time
#if defined(SUPP_ICEORYX)
		} else if (work->proto == PROTO_ICEORYX_BRIDGE) {
			nng_msg *icemsg = msg;
			nng_msg *decode_msg = NULL;
			//log_debug("pld:%s", (char *)nng_msg_payload_ptr(msg));
			// convert iceoryx msg to nng mqtt msg
			rv = nano_iceoryx_recv_nng_msg(work->iceoryx_suber, icemsg, &decode_msg);
			if (rv != 0) {
				log_error("Failed to decode iceoryx msg %d", rv);
				work->state = RECV;
				nng_aio_set_prov_data(work->aio, work->iceoryx_suber);
				nng_ctx_recv(work->extra_ctx, work->aio);
				break;
			}
			msg = decode_msg;
			nng_msg_set_cmd_type(msg, CMD_PUBLISH);
			nng_msg_iceoryx_free(icemsg, work->iceoryx_suber);
#endif
		}
		// processing what we got now
		work->msg       = msg;
		work->pid       = nng_msg_get_pipe(work->msg);
		work->cparam    = nng_msg_get_conn_param(work->msg);
		work->proto_ver = conn_param_get_protover(work->cparam);
		work->flag      = nng_msg_cmd_type(msg);

		if (work->flag == CMD_SUBSCRIBE) {
			smsg = work->msg;
			work->msg_ret = NULL;

			if ((work->sub_pkt = nng_alloc(
			         sizeof(packet_subscribe))) == NULL)
				log_error("nng_alloc");
			memset(work->sub_pkt, '\0', sizeof(packet_subscribe));

			if ((rv = decode_sub_msg(work)) != 0 ||
			    (rv = sub_ctx_handle(work)) != 0) {
				work->code = rv;
				log_error("sub_handler: [%d]", rv);
			}
			bridge_sub_handler(work);

			// TODO not all codes needs to close the pipe
			if (work->code != SUCCESS) {
				if (work->msg_ret) {
					for (size_t i = 0; i < cvector_size(work->msg_ret); i++)
						nng_msg_free(work->msg_ret[i]);
					cvector_free(work->msg_ret);
				}
				if (work->sub_pkt)
					sub_pkt_free(work->sub_pkt);
				// free conn_param due to clone in protocol layer
				conn_param_free(work->cparam);

				work->state = CLOSE;
				nng_aio_finish(work->aio, 0);
				break;
			}

			// TODO Error handling
			if (0 != (rv = encode_suback_msg(smsg, work)))
				log_error("error in encode suback: [%d]", rv);

			sub_pkt_free(work->sub_pkt);
			// handle retain (Retain flag handled in npipe)
			work->msg = NULL;
			if (work->msg_ret) {
				log_debug("retain msg [%p] size [%ld] \n",
				    work->msg_ret, cvector_size(work->msg_ret));
				for (int i = 0; i < cvector_size(work->msg_ret) &&
				     check_msg_exp(work->msg_ret[i],
				         nng_mqtt_msg_get_publish_property(
				             work->msg_ret[i])); i++) {
					nng_msg *m = work->msg_ret[i];
					work->msg = m;
					work->pub_packet = (struct pub_packet_struct *) nng_zalloc(
										sizeof(struct pub_packet_struct));
					void *proto_data = NULL;
					uint8_t ver = nng_mqtt_msg_get_connect_proto_version(work->msg);
					if (SUCCESS == decode_pub_message(work, ver)) {
						bool  bridged = false;
						proto_data = nng_msg_get_proto_data(work->msg);
						// TODO replace bridge bool with sub retain bool
						// bridged = nng_mqtt_msg_get_sub_retain_bool(work->msg, true);
						if (proto_data != NULL)
							bridged = nng_mqtt_msg_get_bridge_bool(work->msg);
						if (bridged) {
							bridge_handle_topic_reflection(
							    work, &work->config->bridge);
						}
						// dont modify original retain msg;
						nng_msg *rmsg = NULL;
						if (nng_msg_dup(&rmsg, work->msg) != 0) {
							log_error("System Failure while duplicating retain msg");
						} else {
							if (work->proto_ver == MQTT_VERSION_V5) {
								nng_msg_set_cmd_type(rmsg,CMD_PUBLISH_V5);
							} else {
								nng_msg_set_cmd_type(rmsg, CMD_PUBLISH);
							}
						}
						// nng_msg_set_proto_data(rmsg, NULL, proto_data);
						if (encode_pub_message(rmsg, work, PUBLISH)) {
							nng_mqtt_msg_set_sub_retain_bool(rmsg, true);
							nng_aio_set_msg(work->aio, rmsg);
							nng_aio_set_prov_data(work->aio, &work->pid.id);
							nng_ctx_send(work->ctx, work->aio);
						} else
							log_warn("encode retain msg failed!");
					} else {
						log_warn("decode retain msg failed!");
					}
					free_pub_packet(work->pub_packet);
					work->pub_packet = NULL;
					cvector_free(work->pipe_ct->msg_infos);
					work->pipe_ct->msg_infos = NULL;
					// free the ref due to dbtree_find_retain
					nng_msg_free(m);
				}
				cvector_free(work->msg_ret);
			}
			nng_msg_set_cmd_type(smsg, CMD_SUBACK);
			nng_aio_set_prov_data(work->aio, &work->pid.id);
			nng_aio_set_msg(work->aio, smsg);
			work->msg   = NULL;
			work->state = SEND;
			nng_ctx_send(work->ctx, work->aio);
			smsg = NULL;
			nng_aio_finish(work->aio, 0);
			// free conn_param in SEND state
			break;
		} else if (work->flag == CMD_UNSUBSCRIBE) {
			smsg = work->msg;
			if ((work->unsub_pkt = nng_alloc(
			         sizeof(packet_unsubscribe))) == NULL)
				log_error("nng_alloc");

			if ((rv = decode_unsub_msg(work)) != 0 ||
			    (rv = unsub_ctx_handle(work)) != 0) {
				log_error("unsub_handler [%d]", rv);
			}
			// proxy unsub action to bridge
			bridge_sub_handler(work);

			if (0 != (rv = encode_unsuback_msg(smsg, work)))
				log_error("in unsuback [%d]", rv);

			// free unsub_pkt
			unsub_pkt_free(work->unsub_pkt);
			nng_aio_set_prov_data(work->aio, &work->pid.id);
			nng_aio_set_msg(work->aio, work->msg);
			work->msg   = NULL;
			work->state = SEND;
			nng_ctx_send(work->ctx, work->aio);
			smsg = NULL;
			nng_aio_finish(work->aio, 0);
			//free conn_param in SEND state
			break;
		} else if (work->flag == CMD_PUBLISH) {
			// Set V4/V5 flag for publish msg
			if (work->proto_ver == MQTT_VERSION_V5) {
				nng_msg_set_cmd_type(msg, CMD_PUBLISH_V5);
			} else {
				nng_msg_set_cmd_type(msg, CMD_PUBLISH);
			}
			work->code = handle_pub(
			    work, work->pipe_ct, work->proto_ver, false);
			if (work->proto == PROTO_HTTP_SERVER ||
			    work->proto == PROTO_AWS_BRIDGE) {
				nng_msg *rep_msg;
				nng_msg_alloc(&rep_msg, 0);
				nng_aio_set_msg(work->aio, rep_msg);
				if (work->code == SUCCESS)
					work->state = WAIT;
				else
					work->state = SEND;
				nng_ctx_send(work->extra_ctx, work->aio);
				break;
			}
			if (work->code != SUCCESS) {
				//what if extra ctx brings a wrong msg?
				if (work->proto != PROTO_MQTT_BROKER) {
					work->state = SEND;
					nng_aio_finish(work->aio, 0);
					// break or return?
					break;
				}
				work->state = CLOSE;
				free_pub_packet(work->pub_packet);
				work->pub_packet = NULL;
				cvector_free(work->pipe_ct->msg_infos);
				// free conn_param due to clone in protocol layer
				conn_param_free(work->cparam);
				nng_aio_finish(work->aio, 0);
				// break or return?
				break;
			}
		} else if (work->flag == CMD_CONNACK) {
			uint8_t *body        = nng_msg_body(work->msg);
			uint8_t  reason_code = *(body + 1);
			if (work->proto == PROTO_MQTT_BROKER) {
				// Return CONNACK to clients of broker
				nng_aio_set_prov_data(work->aio, &work->pid.id);
				// clone for sending connect event notification
				nng_msg_clone(work->msg);
				nng_aio_set_msg(work->aio, work->msg);
				nng_ctx_send(work->ctx, work->aio);
			}
			smsg = nano_msg_notify_connect(work->cparam, reason_code);
			hook_entry(work, reason_code);
			// Set V4/V5 flag for publish notify msg
			nng_msg_set_cmd_type(smsg, CMD_PUBLISH);
			nng_msg_free(work->msg);
			work->msg = smsg;
			handle_pub(work, work->pipe_ct,
			    MQTT_PROTOCOL_VERSION_v311, true);
			// set flag after hanlde_pub to avoid bridging logic
			work->flag = CMD_PUBLISH;
			// remember to free conn_param in WAIT 
			// due to clone in protocol layer
		} else if (work->flag == CMD_DISCONNECT_EV) {
			// Now v4 as default/send V5 notify msg?
			hook_entry(work, 0);
			nng_msg_set_cmd_type(msg, CMD_PUBLISH);
			handle_pub(work, work->pipe_ct,
			    MQTT_PROTOCOL_VERSION_v311, true);
			work->flag = CMD_PUBLISH;
			// TODO set reason code
			// uint8_t *payload = nng_msg_payload_ptr(work->msg);
			// uint8_t reason_code = *(payload+16);
			// free client ctx
			if (dbhash_check_id(work->pid.id)) {
				destroy_sub_client(work->pid.id, work->db);
			}
			// bridge's will msg only valid at remote
			if (work->proto != PROTO_MQTT_BRIDGE) {
				if (conn_param_get_will_flag(work->cparam) ==
				        0 ||
				    !conn_param_get_will_topic(work->cparam) ||
				    !conn_param_get_will_msg(work->cparam)) {
					// no will msg - free the cp
					conn_param_free(work->cparam);
				} else {
					// set to END to send will msg
					// TBD: relay last will msg for
					// bridging client?
					work->state = END;
					// leave cp for will msg
					nng_aio_finish(work->aio, 0);
					break;
				}
			}
		}
		work->state = WAIT;
		nng_aio_finish(work->aio, 0);
		break;
	case WAIT:
		// do not access to cparam
		log_debug("WAIT ^^^^ ctx%d ^^^^", work->ctx.id);
#if defined(SUPP_PLUGIN)
		work->user_property = NULL;
#endif
		if (nng_msg_get_type(work->msg) == CMD_PUBLISH) {
			if ((rv = nng_aio_result(work->aio)) != 0) {
				log_error("WAIT nng aio result error: %d", rv);
				NANO_NNG_FATAL("WAIT nng_ctx_recv/send", rv);	// shall nerver reach here
			}
			smsg      = work->msg; // reuse the same msg
			cvector(mqtt_msg_info) msg_infos;
			msg_infos = work->pipe_ct->msg_infos;

			log_trace("total subscribed pipes: %ld", cvector_size(msg_infos));
			if (cvector_size(msg_infos))
				if (encode_pub_message(smsg, work, PUBLISH)) {
					for (int i = 0; i < cvector_size(msg_infos) && rv== 0; ++i) {
						msg_info = &msg_infos[i];
						nng_msg_clone(smsg);
						work->pid.id = msg_info->pipe;
						nng_aio_set_prov_data(work->aio, &work->pid.id);
						work->msg = smsg;
						nng_aio_set_msg(work->aio, work->msg);
						nng_ctx_send(work->ctx, work->aio);
					}
				}
			work->msg = smsg;

			// bridge logic first
			if (work->config->bridge_mode) {
				bridge_pub_handler(work);
#if defined(SUPP_AWS_BRIDGE)
				aws_bridge_forward(work);
#endif
#if defined(SUPP_PLUGIN)
				/* after bridge_handler which will dup user property */
				if (work->user_property != NULL) {
					property_remove(work->pub_packet->var_header
								.publish.properties, work->user_property->id);
					if (work->pub_packet->var_header.publish.properties != NULL) {
						property_free(work->pub_packet->var_header.publish.properties);
					}
				}
#endif
			}
			//check webhook & rule engine
			conf_web_hook *hook_conf = &(work->config->web_hook);
			conf_exchange *exge_conf = &(work->config->exchange);
			uint8_t rule_opt = RULE_ENG_OFF;
#if defined(SUPP_RULE_ENGINE)
			rule_opt = work->config->rule_eng.option;
#endif
			uint8_t iceoryx_opt = 0;
#if defined(SUPP_ICEORYX)
			iceoryx_opt = 1;
#endif
			if (hook_conf->enable || exge_conf->count > 0 || 
			        rule_opt != RULE_ENG_OFF || iceoryx_opt == 1) {
				work->state = SEND;
				nng_aio_finish(work->aio, 0);
				break;
			}
			// skip one IO switching
			nng_msg_free(work->msg);
			smsg = NULL;
			work->msg = NULL;
			// free conn_param due to clone in protocol layer
			conn_param_free(work->cparam);
			free_pub_packet(work->pub_packet);
			work->pub_packet = NULL;
			cvector_free(msg_infos);
			work->pipe_ct->msg_infos = NULL;
			init_pipe_content(work->pipe_ct);
			work->state = RECV;
			if (work->proto != PROTO_MQTT_BROKER) {
				nng_ctx_recv(work->extra_ctx, work->aio);
			} else {
				nng_ctx_recv(work->ctx, work->aio);
			}
		} else if (nng_msg_cmd_type(work->msg) == CMD_PUBACK ||
		    nng_msg_cmd_type(work->msg) == CMD_PUBREL ||
		    nng_msg_cmd_type(work->msg) == CMD_PUBCOMP) {
			nng_msg_free(work->msg);
			work->msg   = NULL;
			work->state = RECV;
			nng_ctx_recv(work->ctx, work->aio);
			break;
		} else {
			log_debug("broker has nothing to do");
			if (work->msg != NULL)
				nng_msg_free(work->msg);
			work->msg   = NULL;
			work->state = RECV;
			nng_ctx_recv(work->ctx, work->aio);
			break;
		}
		break;
	case SEND:
		log_debug("SEND ^^^^ ctx%d ^^^^", work->ctx.id);
#if defined(SUPP_RULE_ENGINE)
		if (work->flag == CMD_PUBLISH && work->config->rule_eng.option != RULE_ENG_OFF) {
			rule_engine_insert_sql(work);
		}
#endif
#if defined(SUPP_ICEORYX)
		if (work->flag == CMD_PUBLISH && work->msg != NULL &&
		        true == nano_iceoryx_topic_filter("ice/fwd",
		        work->pub_packet->var_header.publish.topic_name.body,
		        work->pub_packet->var_header.publish.topic_name.len)) {
			if (0 != (rv = nano_iceoryx_send_nng_msg(
			        work->iceoryx_puber, work->msg, &work->iceoryx_sock))) {
				log_error("Failed to send iceoryx %d", rv);
			}
		}
#endif
		// external hook here
		hook_entry(work, 0);

		if (NULL != work->msg) {
			nng_msg_free(work->msg);
			work->msg = NULL;
		}
		if ((rv = nng_aio_result(work->aio)) != 0) {
			log_error("SEND nng_ctx_send error %d", rv);
		}
		if (work->pub_packet != NULL) {
			free_pub_packet(work->pub_packet);
			work->pub_packet = NULL;
		}
		if (work->pipe_ct->msg_infos != NULL) {
			cvector_free(work->pipe_ct->msg_infos);
			work->pipe_ct->msg_infos = NULL;
			init_pipe_content(work->pipe_ct);
		}
		// free conn_param due to clone in protocol layer
		conn_param_free(work->cparam);
		work->state = RECV;
		work->flag  = 0;
		if (work->proto == PROTO_MQTT_BROKER) {
			nng_ctx_recv(work->ctx, work->aio);
#if defined(SUPP_ICEORYX)
		} else if (work->proto == PROTO_ICEORYX_BRIDGE) {
			nng_aio_set_prov_data(work->aio, work->iceoryx_suber);
			nng_ctx_recv(work->extra_ctx, work->aio);
#endif
		} else{
			nng_ctx_recv(work->extra_ctx, work->aio);
		}
		break;
	case END:
		log_debug("END ^^^^ ctx%d ^^^^ ", work->ctx.id);
		// send disconnect event msg first
		if (nng_msg_get_type(work->msg) == CMD_PUBLISH) {
			if ((rv = nng_aio_result(work->aio)) != 0) {
				log_error("WAIT nng aio result error: %d", rv);
			}
			smsg      = work->msg; // reuse the same msg

			cvector(mqtt_msg_info) msg_infos;
			msg_infos = work->pipe_ct->msg_infos;

			log_debug("total pipes: %ld", cvector_size(msg_infos));
			//TODO encode abstract msg only
			if (cvector_size(msg_infos))
				if (encode_pub_message(smsg, work, PUBLISH))
					for (int i=0; i<cvector_size(msg_infos); ++i) {
						msg_info = &msg_infos[i];
						nng_msg_clone(smsg);
						work->pid.id = msg_info->pipe;
						nng_aio_set_prov_data(work->aio, &work->pid.id);
						work->msg = smsg;
						nng_aio_set_msg(work->aio, work->msg);
						nng_ctx_send(work->ctx, work->aio);
					}
			hook_entry(work, 0);
			nng_msg_free(smsg);
			smsg = NULL;
			work->msg = NULL;
			free_pub_packet(work->pub_packet);
			work->pub_packet = NULL;
			cvector_free(work->pipe_ct->msg_infos);
			work->pipe_ct->msg_infos = NULL;
			init_pipe_content(work->pipe_ct);

			// processing will msg
			if (conn_param_get_will_flag(work->cparam) &&
			    (msg = nano_pubmsg_composer(&msg,
			         conn_param_get_will_retain(work->cparam),
			         conn_param_get_will_qos(work->cparam),
			         (mqtt_string *) conn_param_get_will_msg(
			             work->cparam),
			         (mqtt_string *) conn_param_get_will_topic(
			             work->cparam),
			         conn_param_get_protover(work->cparam),
			         nng_clock())) != NULL) {
				work->msg = msg;
				work->flag = CMD_PUBLISH;
				// Set V4/V5 flag for publish msg
				if (conn_param_get_protover(work->cparam) == 5) {
					property *will_property =
					    conn_param_get_will_property(
					        work->cparam);
					nng_msg_set_cmd_type(
					    msg, CMD_PUBLISH_V5);
					handle_pub(work, work->pipe_ct,
					    MQTT_PROTOCOL_VERSION_v5, false);
					work->pub_packet->var_header.publish
					    .properties = property_pub_by_will(
					    will_property);
					work->pub_packet->var_header.publish
					    .prop_len = get_mqtt_properties_len(
					    work->pub_packet->var_header
					        .publish.properties);
				} else {
					nng_msg_set_cmd_type(msg, CMD_PUBLISH);
					handle_pub(work, work->pipe_ct,
					    MQTT_PROTOCOL_VERSION_v311, false);
				}
				work->state = WAIT;
				nng_aio_finish(work->aio, 0);
			} else {
				// free Conn_param once more in case invalid last-will msg
				conn_param_free(work->cparam);
				if (work->msg != NULL)
					nng_msg_free(work->msg);
				work->msg = NULL;
				work->state = RECV;
				if (work->proto == PROTO_MQTT_BROKER) {
					nng_ctx_recv(work->ctx, work->aio);
				} else {
					nng_ctx_recv(work->extra_ctx, work->aio);
				}
			}
		}
		conn_param_free(work->cparam);
		break;
	case CLOSE:
		log_debug(" CLOSE ^^^^ ctx%d ^^^^", work->ctx.id);
		smsg = nano_dismsg_composer(work->code, NULL, NULL, NULL);
		nng_msg_free(work->msg);
		work->msg = smsg;
		// compose a disconnect msg
		nng_aio_set_prov_data(work->aio, &work->pid.id);
		// clone for sending connect event notification
		nng_aio_set_msg(work->aio, work->msg);
		nng_ctx_send(work->ctx, work->aio);

		// clear reason code
		work->code = SUCCESS;
		work->state = RECV;
		nng_ctx_recv(work->ctx, work->aio);
		break;
	default:
		NANO_NNG_FATAL("bad state!", NNG_ESTATE);
		break;
	}
}

struct work *
alloc_work(nng_socket sock)
{
	struct work *w;
	int          rv;

	if ((w = nng_alloc(sizeof(*w))) == NULL) {
		NANO_NNG_FATAL("nng_alloc", NNG_ENOMEM);
	}
	if ((rv = nng_aio_alloc(&w->aio, server_cb, w)) != 0) {
		NANO_NNG_FATAL("nng_aio_alloc", rv);
	}
	if ((rv = nng_ctx_open(&w->ctx, sock)) != 0) {
		NANO_NNG_FATAL("nng_ctx_open", rv);
	}

	w->pipe_ct = nng_alloc(sizeof(struct pipe_content));
	init_pipe_content(w->pipe_ct);
	w->pub_packet = NULL;
	w->node       = NULL;
	w->state      = INIT;
	return (w);
}

nano_work *
proto_work_init(nng_socket sock, nng_socket extrasock, uint8_t proto,
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

#if defined(SUPP_ICEORYX)
	w->iceoryx_suber = NULL;
	w->iceoryx_puber = NULL;
#endif

	w->sqlite_db = NULL;
#if defined(NNG_SUPP_SQLITE)
	nng_socket_get_ptr(sock, NMQ_OPT_MQTT_QOS_DB, &w->sqlite_db);
#endif

	// only create ctx for extra ctx that are required to receive msg
	if (config->http_server.enable && proto == PROTO_HTTP_SERVER) {
		if ((rv = nng_ctx_open(&w->extra_ctx, extrasock)) != 0) {
			NANO_NNG_FATAL("nng_ctx_open", rv);
		}
#if defined(SUPP_ICEORYX)
	} else if (proto == PROTO_ICEORYX_BRIDGE) {
			if ((rv = nng_ctx_open(&w->extra_ctx, extrasock)) != 0) {
				NANO_NNG_FATAL("nng_ctx_open", rv);
			}
#endif
	} else if (config->bridge_mode) {
		if (proto == PROTO_MQTT_BRIDGE) {
			if ((rv = nng_ctx_open(&w->extra_ctx, extrasock)) != 0) {
				NANO_NNG_FATAL("nng_ctx_open", rv);
			}
		} else if (proto == PROTO_AWS_BRIDGE) {
			if ((rv = nng_ctx_open(&w->extra_ctx, extrasock)) != 0) {
				NANO_NNG_FATAL("nng_ctx_open", rv);
			}
		}
	}

	if(config->web_hook.enable || config->exchange.count > 0) {
		if ((rv = nng_push0_open(&w->hook_sock)) != 0) {
			NANO_NNG_FATAL("nng_socket", rv);
		}
		char *hook_ipc_url = config->hook_ipc_url == NULL
		    ? HOOK_IPC_URL
		    : config->hook_ipc_url;
		if ((rv = nng_dial(w->hook_sock, hook_ipc_url, NULL, 0)) != 0) {
			NANO_NNG_FATAL("hook nng_dial", rv);
		}
	}

	return w;
}

static dbtree           *db        = NULL;
static dbtree           *db_ret    = NULL;
// TODO For HTTP SUB/UNSUB usage
static struct hashmap_s *cid_table = NULL;

struct hashmap_s *
get_hashmap(void)
{
	return cid_table;
}

dbtree *
get_broker_db(void)
{
	return db;
}

int
broker(conf *nanomq_conf)
{
	int        rv, i;
	uint64_t   num_work;
	nng_socket sock;
	nng_socket *bridge_sock;
	nng_pipe   pipe_id;
	// add the num of other proto
	nanomq_conf->total_ctx = nanomq_conf->parallel;		// match with num of aio
	num_work = nanomq_conf->parallel;					// match with num of works


#if defined(SUPP_RULE_ENGINE)
	conf_rule *cr = &nanomq_conf->rule_eng;

#if defined(NNG_SUPP_SQLITE)
	if (cr->option & RULE_ENG_SDB) {
		nanomq_client_sqlite(cr, false);
	}
#endif

#if defined(SUPP_MYSQL)
	if (cr->option & RULE_ENG_MDB) {
		nanomq_client_mysql(cr, false);
	}
#endif

#if defined(FDB_SUPPORT)
	if (cr->option & RULE_ENG_FDB) {
		pthread_t   netThread;
		fdb_error_t err =
		    fdb_select_api_version(FDB_API_VERSION);
		if (err) {
			log_debug("select API version error: %s",
			    fdb_get_error(err));
			exit(1);
		}
		FDBDatabase *fdb   = openDatabase(&netThread);
		nanomq_conf->rule_eng.rdb[1] = (void *) fdb;
	}
#endif

	if (cr->option & RULE_ENG_RPB) {
		for (int i = 0; i < cvector_size(cr->rules); i++) {
			if (RULE_FORWORD_REPUB == cr->rules[i].forword_type) {
				int              index = 0;
				nng_socket *sock  = (nng_socket *) nng_alloc(
				    sizeof(nng_socket));
				nano_client(sock, cr->rules[i].repub);
			}

		}
	}
#endif

	// init tree
	dbtree_create(&db);
	if (db == NULL) {
		printf("NNL_ERROR error in db create");
	}
	dbtree_create(&db_ret);
	if (db_ret == NULL) {
		printf("NNL_ERROR error in db create");
	}

	dbhash_init_cached_table();
	dbhash_init_pipe_table();
	dbhash_init_alias_table();

	log_debug("db init finished");
	/*  Create the socket. */
	nanomq_conf->db_root = db;
	sock.id              = 0;
	sock.data            = nanomq_conf;
	rv                   = nng_nmq_tcp0_open(&sock);
	if (rv != 0) {
		NANO_NNG_FATAL("nng_nmq_tcp0_open", rv);
	}
	log_debug("listener init finished");

	// HTTP Service
	nng_socket inproc_sock = { 0 };

	if (nanomq_conf->http_server.enable || nanomq_conf->bridge_mode) {
		log_debug("HTTP service initialization");
		rv = nng_rep0_open(&inproc_sock);
		if (rv != 0) {
			NANO_NNG_FATAL("nng_rep0_open", rv);
		}
		// set 4 ctx for HTTP as default
		if (nanomq_conf->http_server.enable) {
			nanomq_conf->total_ctx += HTTP_CTX_NUM;
			num_work += HTTP_CTX_NUM;
		}
	}
	log_debug("HTTP init finished");

#if defined(SUPP_ICEORYX)
	// This is for iceoryx
	nanomq_conf->total_ctx += HTTP_CTX_NUM;
	num_work += HTTP_CTX_NUM;
#endif

	// Exchange service
	for (int i = 0; i < nanomq_conf->exchange.count; i++) {
		conf_exchange_node *node = nanomq_conf->exchange.nodes[i];
		if (node == NULL) {
			log_error("Wrong exchange %d configuration!", i);
			continue;
		}
		node->sock = (nng_socket *) nng_alloc(sizeof(nng_socket));
		// exchange sock is an embedded Req/Rep sock for MQTT Stream
		if ((rv = nng_exchange_client_open(node->sock)) != 0) {
			log_error("nng_exchange_client_open failed %d", rv);
		} else {
			// nng_socket_set_ms(*node->sock, NNG_OPT_RECVMAXSZ, 0xFFFFFFFFu);
			nng_socket_set_ptr(*node->sock, NNG_OPT_EXCHANGE_BIND, (void *)node);
		}
		log_debug("exchange %d init finished!\n", i);
	}
	// Hook service
	if (nanomq_conf->web_hook.enable || nanomq_conf->exchange.count > 0) {
		start_hook_service(nanomq_conf);
		log_debug("Hook service started");
	}

	// caculate total ctx first
	if (nanomq_conf->bridge_mode) {
		for (size_t t = 0; t < nanomq_conf->bridge.count; t++) {
			conf_bridge_node *node = nanomq_conf->bridge.nodes[t];
			if (node->enable) {
				// each bridge ctx is init with a broker ctx
				nanomq_conf->total_ctx += node->parallel * 2;
				num_work += node->parallel;
			}
		}

#if defined(SUPP_AWS_BRIDGE)
		for (size_t c = 0; c < nanomq_conf->aws_bridge.count; c++) {
			log_debug("AWS bridgging service initialization");
			conf_bridge_node *node =
			    nanomq_conf->aws_bridge.nodes[c];
			if (node->enable) {
				nanomq_conf->total_ctx += node->parallel * 2;
				num_work += node->parallel;
			}
		}
#endif
		log_trace("total ctx num: %ld", nanomq_conf->total_ctx);
	}

	// init bridging client
	if (nanomq_conf->bridge_mode) {
		for (size_t t = 0; t < nanomq_conf->bridge.count; t++) {
			conf_bridge_node *node = nanomq_conf->bridge.nodes[t];
			if (node->enable) {
				node->sock = (nng_socket *) nng_alloc(
				    sizeof(nng_socket));
#if defined(SUPP_QUIC)
				if (node->hybrid) {
					hybrid_bridge_client(node->sock, nanomq_conf, node);
				} else {
					bridge_client(node->sock, nanomq_conf, node);
				}
#else
				bridge_client(node->sock, nanomq_conf, node);
#endif
			}
		}
		log_debug("bridge init finished");
	}
	// CTX for MQTT Broker service
	struct work **works = nng_zalloc(num_work * sizeof(struct work *));
	// create broker ctx
	for (i = 0; i < nanomq_conf->parallel; i++) {
		works[i] = proto_work_init(sock, inproc_sock,
		    PROTO_MQTT_BROKER, db, db_ret, nanomq_conf);
	}

	// create bridge ctx
	// only create ctx when there is sub topics
	size_t tmp = nanomq_conf->parallel;
	if (nanomq_conf->bridge_mode) {
		log_debug("MQTT bridging service initialization");
		// iterates all bridge targets
		for (size_t t = 0; t < nanomq_conf->bridge.count; t++) {
			conf_bridge_node *node = nanomq_conf->bridge.nodes[t];
			if (node->enable) {
				bridge_sock = node->sock;
				for (i = tmp; i < (tmp + node->parallel); i++) {
					works[i] = proto_work_init(sock,
					    *bridge_sock, PROTO_MQTT_BRIDGE,
					    db, db_ret, nanomq_conf);
					works[i]->node = node;
				}
				tmp += node->parallel;
			}
		}

#if defined(SUPP_AWS_BRIDGE)
		for (size_t t = 0; t < nanomq_conf->aws_bridge.count; t++) {
			conf_bridge_node *node =
			    nanomq_conf->aws_bridge.nodes[t];
			if (node->enable) {
				for (i = tmp; i < (tmp + node->parallel);
				     i++) {
					works[i] =
					    proto_work_init(sock, inproc_sock,
					        PROTO_AWS_BRIDGE, db, db_ret, nanomq_conf);
				}
				tmp += node->parallel;
				aws_bridge_client(node);
			}
		}
#endif
	}

	// create http server ctx
	if (nanomq_conf->http_server.enable) {
		log_debug("http context init");
		for (i = tmp; i < tmp + HTTP_CTX_NUM; i++) {
			works[i] = proto_work_init(sock, inproc_sock,
			    PROTO_HTTP_SERVER, db, db_ret, nanomq_conf);
		}
		tmp += HTTP_CTX_NUM;
	}

#if defined(SUPP_ICEORYX)
	nng_socket iceoryx_sock;
	const char *iceoryx_service = "NanoMQ-Service";
	const char *iceoryx_instance = "NanoMQ-Instance";
	const char *iceoryx_event_sub = "topic";
	const char *iceoryx_event_pub = "ice/fwd";
	nng_iceoryx_open(&iceoryx_sock, "NanoMQ-Iceoryx");

	nng_iceoryx_suber *suber;
	nng_iceoryx_sub(&iceoryx_sock, "NanoMQ-Iceoryx-Suber",
		iceoryx_service, iceoryx_instance, iceoryx_event_sub, &suber);

	nng_iceoryx_puber *puber;
	nng_iceoryx_pub(&iceoryx_sock, "NanoMQ-Iceoryx-Puber",
		iceoryx_service, iceoryx_instance, iceoryx_event_pub, &puber);

	// create iceoryx ctx
	log_debug("iceoryx context init");
	for (i = tmp; i < tmp + HTTP_CTX_NUM; i++) {
		works[i] = proto_work_init(sock, iceoryx_sock,
		    PROTO_ICEORYX_BRIDGE, db, db_ret, nanomq_conf);
	}
	tmp += HTTP_CTX_NUM;
#endif

	// Init exchange part in hook
	if (nanomq_conf->exchange.count > 0) {
		hook_exchange_init(nanomq_conf, num_work);
		// create exchange senders in hook
		hook_exchange_sender_init(nanomq_conf, works, num_work);
		for (i = 0; i < nanomq_conf->exchange.count; i++) {
			nng_socket *mq_sock = nanomq_conf->exchange.nodes[i]->sock;
			nng_listener mq_listener;
			if (nanomq_conf->exchange.nodes[i]->exchange_url == NULL ||
				strlen(nanomq_conf->exchange.nodes[i]->exchange_url) == 0) {
				log_error("Exchange url is not set");
			} else if ((rv = nano_listen(*mq_sock, nanomq_conf->exchange.nodes[i]->exchange_url, &mq_listener, 0, nanomq_conf)) != 0) {
				NANO_NNG_FATAL("broker nng_listen", rv);
			}
			nng_listener_set_size(mq_listener, NNG_OPT_RECVMAXSZ, 0xFFFFFFFFu);
		}
	}

	if (nanomq_conf->enable) {
		if (nanomq_conf->url) {
			if ((rv = nano_listen(sock, nanomq_conf->url, NULL, 0,
			         nanomq_conf)) != 0) {
				NANO_NNG_FATAL("broker nng_listen", rv);
			}
		}

		for (i = 0; i < nanomq_conf->tcp_list.count; i++) {
			if ((rv = nano_listen(sock,
			         nanomq_conf->tcp_list.nodes[i]->url, NULL, 0,
			         nanomq_conf)) != 0) {
				NANO_NNG_FATAL("broker nng_listen", rv);
			}
		}
	}

	// read from command line & config file
	if (nanomq_conf->websocket.enable) {
		if ((rv = nano_listen(
		         sock, nanomq_conf->websocket.url, NULL, 0, nanomq_conf)) != 0) {
			NANO_NNG_FATAL("nng_listen ws", rv);
		}
	}

	if (nanomq_conf->tls_list.count > 0) {
		for (i = 0; i < nanomq_conf->tls_list.count; i++) {
			nng_listener tls_listener;

			if ((rv = nng_listener_create(&tls_listener, sock,
			         nanomq_conf->tls_list.nodes[i]->url)) != 0) {
				NANO_NNG_FATAL("nng_listener_create tls", rv);
			}
			nng_listener_set(tls_listener, NANO_CONF, nanomq_conf,
			    sizeof(conf));

			init_listener_tls(
			    tls_listener, nanomq_conf->tls_list.nodes[i]);
			if ((rv = nng_listener_start(tls_listener, 0)) != 0) {
				NANO_NNG_FATAL("nng_listener_start tls", rv);
			}
		}
	}

	if (nanomq_conf->tls.enable) {
		if (nanomq_conf->tls.url) {
			nng_listener tls_listener;
			if ((rv = nng_listener_create(&tls_listener, sock,
			         nanomq_conf->tls.url)) != 0) {
				NANO_NNG_FATAL("nng_listener_create tls", rv);
			}
			nng_listener_set(tls_listener, NANO_CONF, nanomq_conf,
			    sizeof(conf));
			init_listener_tls(tls_listener, &nanomq_conf->tls);
			if ((rv = nng_listener_start(tls_listener, 0)) != 0) {
				NANO_NNG_FATAL("nng_listener_start tls", rv);
			}
		}

		// TODO: multi for websocket
		if (nanomq_conf->websocket.enable) {
			nng_listener wss_listener;
			if ((rv = nng_listener_create(&wss_listener, sock,
			         nanomq_conf->websocket.tls_url)) != 0) {
				NANO_NNG_FATAL("nng_listener_create wss", rv);
			}
			nng_listener_set(
					wss_listener, NANO_CONF, nanomq_conf, sizeof(nanomq_conf));

			init_listener_tls(wss_listener, &nanomq_conf->tls);
			if ((rv = nng_listener_start(wss_listener, 0)) != 0) {
				NANO_NNG_FATAL("nng_listener_start wss", rv);
			}
		}
	}

	if (nanomq_conf->http_server.enable || nanomq_conf->bridge_mode) {
		if ((rv = nano_listen(inproc_sock, INPROC_SERVER_URL, NULL, 0,
		         nanomq_conf)) != 0) {
			NANO_NNG_FATAL("nng_listen " INPROC_SERVER_URL, rv);
		}
	}

#if defined(SUPP_ICEORYX)
	for (i = 0; i < num_work; i++) {
		works[i]->iceoryx_suber = suber;
		works[i]->iceoryx_puber = puber;
		works[i]->iceoryx_sock.data  = iceoryx_sock.data;
		works[i]->iceoryx_sock.id    = iceoryx_sock.id;
	}
#endif

	for (i = 0; i < num_work; i++) {
		server_cb(works[i]); // this starts them going (INIT state)
	}

	if (nanomq_conf->http_server.enable) {
		nanomq_conf->http_server.broker_sock = &sock;
		start_rest_server(nanomq_conf);
	}

	// ipc server for receiving commands from reload command
	// Interact with HTTP external
	if (nanomq_conf->ipc_internal) {
#if !defined(BUILD_APP_LIB)
		nng_socket cmd_sock;
		cmd_work * cmd_works[CMD_PROC_PARALLEL];

		/*  Create the IPC socket for CMD Server. */
		rv = nng_rep0_open(&cmd_sock);
		if (rv != 0) {
			NANO_NNG_FATAL("CMD socket ERROR: nng_rep0_open", rv);
		}

		for (i = 0; i < CMD_PROC_PARALLEL; i++) {
			cmd_works[i] = alloc_cmd_work(cmd_sock, nanomq_conf);
		}

		char *cmd_ipc_url = nanomq_conf->hook_ipc_url == NULL
		    ? CMD_IPC_URL
		    : nanomq_conf->cmd_ipc_url;
		char *ipc_path = strstr(cmd_ipc_url, "ipc://") + strlen("ipc://");

		if (nano_file_exists(ipc_path))
			nng_file_delete(ipc_path);

		if ((rv = nng_listen(cmd_sock, cmd_ipc_url, NULL, 0)) != 0) {
			NANO_NNG_FATAL("nng_listen ipc", rv);
		}

		for (i = 0; i < CMD_PROC_PARALLEL; i++) {
			cmd_server_cb(cmd_works[i]); // this starts them going
			                             // (INIT state)
		}
#else
		log_error("Not support for App lib\n");
#endif
	}

#if defined(SUPP_PLUGIN)
	for (i = 0; i < nanomq_conf->plugin.path_sz; i++) {
		rv = plugin_register(nanomq_conf->plugin.libs[i]->path);
		if (rv != 0) {
			log_error("plugin_register error:%s : %d", nanomq_conf->plugin.libs[i]->path, rv);
		}
	}
#endif
	printf("NanoMQ Broker is started successfully!\n");

#if defined(ENABLE_NANOMQ_TESTS)
	bool is_testing = true;
#else
	bool is_testing = false;
#endif

#if (defined DEBUG)  && (defined ASAN)
	signal(SIGINT, intHandler);
#else
#if !(defined NANO_PLATFORM_WINDOWS)
	struct sigaction  act;
	i = 0;

	memset(&act, 0, sizeof act);
	sigemptyset(&act.sa_mask);
	act.sa_handler = sig_handler;
	act.sa_flags = 0;

	do {
		if (sigaction(all_signals[i], &act, NULL)) {
			fprintf(stderr, "Cannot install signal %d handler: %s.\n", all_signals[i], strerror(errno));
		}
	} while (all_signals[i++] != SIGTERM);
#endif
#endif

#if (defined DEBUG) && (defined ASAN)
	if (is_testing == true) {
		// broker should hang on to accept request.
		nng_msleep(2000);
	}

	for (;;) {
		if (keepRunning == 0 || is_testing == true) {
#if defined(SUPP_RULE_ENGINE)

#if defined(FDB_SUPPORT)
			if (nanomq_conf->rule_eng.option & RULE_ENG_FDB) {
				fdb_database_destroy(
				    nanomq_conf->rule_eng.rdb[1]);
				fdb_stop_network();
			}
#endif
#endif
			conf *conf = works[0]->config;
			if(is_testing == true && (conf->bridge.count > 0 || conf->aws_bridge.count > 0)) {
				// bridge might need more time to response to the resquest
				nng_msleep(8 * 1000); 
			}
			for (size_t t = 0; t < conf->bridge.count; t++) {
				conf_bridge_node *node = conf->bridge.nodes[t];
				size_t aio_count = conf->total_ctx;
				if (node->enable) {
					for (size_t i = 0; i < aio_count; i++) {
						nng_aio_finish_error(node->bridge_aio[i], 0);
						nng_aio_abort(node->bridge_aio[i], NNG_ECLOSED);
						nng_aio_free(node->bridge_aio[i]);
					}
					nng_free(node->bridge_aio, aio_count * sizeof(nng_aio *));
				}
				// free(node->name);
				// free(node->address);
				// free(node->clientid);
				// nng_free(node, sizeof(conf_bridge_node));
			}
			// nng_free(
			//     conf->bridge.nodes, sizeof(conf_bridge_node **));

			for (size_t i = 0; i < num_work; i++) {
				nng_free(works[i]->pipe_ct,
				    sizeof(struct pipe_content));
				nng_free(works[i], sizeof(struct work));
			}
			nng_free(works, num_work * sizeof(struct work *));
			break;
		}
		nng_msleep(6000);
	}
#else
	if (is_testing == false) {
		for (;;) {
			nng_msleep(
			    3600000); // neither pause() nor sleep() portable
		}
	}
#endif
	return 0;
}

void
print_usage(void)
{
	printf("Usage: nanomq { { start | restart [--url <url>] "
	       "[--conf <path>] [-t, --tq_thread <num>]\n                     "
	       "[-T, -max_tq_thread <num>] [-n, --parallel <num>] \n          "
	       "           "
	       "[--old_conf <path>] [-D, --qos_duration <num>] [--http] "
	       "[-p, --port] [-d, --daemon] \n                     "
	       "[--cacert <path>] [-E, --cert <path>] "
	       "[--key <path>] \n                     "
	       "[--keypass <password>] [--verify] [--fail] } \n             "
	       "        "
	       "| reload [--conf <path>] \n                     "
	       "| stop }\n\n");
	printf("Options: \n");
	printf("  --url <url>                Specify listener's url: "
	       "'nmq-tcp://host:port', \r\n                             "
	       "'tls+nmq-tcp://host:port', \r\n                             "
	       "'nmq-ws://host:port/path', \r\n                             "
	       "'nmq-wss://host:port/path'\n");
	printf("  --conf <path>              The path of a specified nanomq "
	       "HOCON style configuration file \n");
	printf("  --old_conf <path>          The path of a specified nanomq "
	       "deprecated version configuration file\n");

	printf("  --http                     Enable http server (default: "
	       "false)\n");
	printf(
	    "  -p, --port <num>           The port of http server (default: "
	    "8081)\n");
	printf(
	    "  -t, --tq_thread <num>      The number of taskq threads used, "
	    "\r\n                             "
	    "`num` greater than 0 and less than 256\n");
	printf(
	    "  -T, --max_tq_thread <num>  The maximum number of taskq threads "
	    "used, \r\n                             "
	    "`num` greater than 0 and less than 256\n");
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
	       "password. \r\n                             "
		   "Only used if the private keyfile is password-protected\n");
	printf("  --verify                   Set verify peer "
	       "certificate (default: false)\n");
	printf("  --fail                     Server will fail if the client "
	       "does not have a \r\n                             "
	       "certificate to send (default: false)\n");
	printf("  --log_level   <level>      The level of log output \n       "
	       "                      "
	       "(level: trace, debug, info, warn, error, fatal)\n             "
	       "                "
	       "(default: warn)\n");
	printf("  --log_file    <file_path>  The path of the log file \n");
	printf(
	    "  --log_stdout  <true|false> Enable/Disable console log output "
	    "(default: true)\n");

#if defined(SUPP_SYSLOG)
	printf("  --log_syslog  <true|false> Enable/Disable syslog output "
	       "(default: false)\n");
#endif

}

int
status_check(int *pid)
{
#ifdef NANO_PLATFORM_WINDOWS
	(void) pid;
	log_warn("Not support on Windows\n");
	return -1;
#else
	char  *data = NULL;
	size_t size = 0;
	char *pid_path = read_env_pid_file();
	if (pid_path == NULL) {
		pid_path = nng_strdup(PID_PATH_NAME);
	}
	int rc;
	if ((rc = nng_file_get(pid_path, (void *) &data, &size)) != 0) {
		nng_strfree(pid_path);
		nng_free(data, size);
		log_warn(".pid file not found or unreadable\n");
		return 1;
	} else {
		if (!nng_file_delete(pid_path)) {
			log_info(".pid file is removed");
			nng_strfree(pid_path);
			return 1;
		}
		nng_strfree(pid_path);
		if ((data) != NULL) {
			if (sscanf(data, "%u", pid) < 1) {
				log_error("read pid from file error!");
				return 1;
			}
			log_info("old pid read, [%u]", *pid);
			nng_free(data, size);

			if ((kill(*pid, 0)) == 0) {
				log_info("there is a running NanoMQ instance "
				          ": pid [%u]",
				    *pid);
				return 0;
			}
		}
		log_error("unexpected error");
		return -1;
	}
#endif
}

int
store_pid()
{
	int  status;
	char pid_c[12] = "";

	snprintf(pid_c, 10, "%d", nng_getpid());
	log_info("%s", pid_c);

	char *pid_path = read_env_pid_file();
	if (pid_path == NULL) {
		pid_path = nng_strdup(PID_PATH_NAME);
	}

	status = nng_file_put(pid_path, pid_c, sizeof(pid_c));
	nng_strfree(pid_path);
	return status;
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
		config->enable = true;
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
// Return config file type
int
file_path_parse(int argc, char **argv, char **file_path)
{
	int   idx = 2;
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
		case OPT_HOCONFILE:
		case OPT_CONFFILE:
			FREE_NONULL(*file_path);
			*file_path = nng_strdup(arg);
			return val;
		default:
			break;
		}
	}

	switch (rv) {
	case NNG_EINVAL:
		fprintf(stderr,
		    "Option %s is invalid.\nTry 'nanomq --help' for "
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
		    "Option %s requires argument.\nTry 'nanomq --help' "
		    "for more information.\n",
		    argv[idx]);
		break;
	default:
		break;
	}

	return rv == -1;
}

int
broker_parse_opts(int argc, char **argv, conf *config)
{
	int   idx = 2;
	char *arg;
	int   val;
	int   rv;

	while ((rv = nng_opts_parse(argc, argv, cmd_opts, &val, &arg, &idx)) ==
	    0) {
		switch (val) {
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
#if defined(ENABLE_LOG)
		case OPT_LOG_LEVEL:
			config->log.level = log_level_num(arg);
			break;
		case OPT_LOG_FILE:
			FREE_NONULL(config->log.file);
			FREE_NONULL(config->log.dir);
			config->log.type |= LOG_TO_FILE;
			char *file_name = strrchr(arg, '/');
			if (file_name) {
				config->log.file = nng_strdup(file_name);
				config->log.dir =
				    nng_strndup(arg, file_name - arg);
			} else {
				config->log.file = nng_strdup(arg);
			}
			break;
		case OPT_LOG_SYSLOG:
#if defined(SUPP_SYSLOG)
			if (nng_strcasecmp("true", arg) == 0) {
				config->log.type |= LOG_TO_SYSLOG;
			} else if (nng_strcasecmp("false", arg) == 0) {
				config->log.type &= ~LOG_TO_SYSLOG;
			}
#else
			fprintf(stderr,
			    "Syslog is not supported, please make sure you "
			    "have built nanomq with option '-D ENABLE_SYSLOG=ON' "
			    ".\n");
			exit(EXIT_FAILURE);
#endif
			break;
		case OPT_LOG_STDOUT:
			if (nng_strcasecmp("true", arg) == 0) {
				config->log.type |= LOG_TO_CONSOLE;
			} else if (nng_strcasecmp("false", arg) == 0) {
				config->log.type &= ~LOG_TO_CONSOLE;
			}
			break;
#endif
		default:
			break;
		}
	}

	switch (rv) {
	case NNG_EINVAL:
		fprintf(stderr,
		    "Option %s is invalid.\nTry 'nanomq --help' for "
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
		    "Option %s requires argument.\nTry 'nanomq --help' "
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
	int i, url, temp, rc;
	int pid = 0;

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

	// Priority: config < environment variables < command opts
	conf_init(nanomq_conf);

	rc = file_path_parse(argc, argv, &nanomq_conf->conf_file);
	if (nanomq_conf->conf_file == NULL) {
		nanomq_conf->conf_file = CONF_PATH_NAME;
		printf("Config file is not specified, use default config file: %s\n", nanomq_conf->conf_file);
	}

	if (!rc) {
		conf_fini(nanomq_conf);
		fprintf(stderr, "Cannot parse command line arguments, quit\n");
		exit(EXIT_FAILURE);
	} else if (rc == OPT_CONFFILE) {
		conf_parse(nanomq_conf);
	} else {
		// HOCON as default
		conf_parse_ver2(nanomq_conf);
	}

	read_env_conf(nanomq_conf);

	if (!broker_parse_opts(argc, argv, nanomq_conf)) {
		conf_fini(nanomq_conf);
		fprintf(stderr, "Cannot parse command line arguments, quit\n");
		exit(EXIT_FAILURE);
	}

	if (nanomq_conf->enable) {
		if (nanomq_conf->tcp_list.count == 0) {
			nanomq_conf->url = nanomq_conf->url != NULL
			    ? nanomq_conf->url
			    : nng_strdup(CONF_TCP_URL_DEFAULT);
		}
	}

	if (nanomq_conf->tls.enable) {
		if (nanomq_conf->tls_list.count == 0) {
			nanomq_conf->tls.url = nanomq_conf->tls.url != NULL
			    ? nanomq_conf->tls.url
			    : nng_strdup(CONF_TLS_URL_DEFAULT);
		}
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
	// Active daemonize
#ifdef NANO_PLATFORM_WINDOWS
	if (nanomq_conf->daemon) {
		log_error("Daemon mode is not supported on Windows");
		rc = -1;
	}
#else
	if (nanomq_conf->daemon == true && process_daemonize()) {
		log_error("Error occurs, cannot daemonize");
		rc = -1;
	}
#endif
#if defined(ENABLE_LOG)
	if ((rc = log_init(&nanomq_conf->log)) != 0) {
		NANO_NNG_FATAL("log_init", rc);
	}
#endif
	print_conf(nanomq_conf);

#if !defined(BUILD_APP_LIB)
	if (store_pid()) {
		log_error("create \"nanomq.pid\" file failed");
	}
#endif

	rc = broker(nanomq_conf);

	return rc == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

void *
broker_start_with_conf(void *nmq_conf)
{

	int rc = 0;
	int pid = 0;
	conf *nanomq_conf = nmq_conf;

	if (!status_check(&pid)) {
		fprintf(stderr,
		    "One NanoMQ instance is still running, a new instance for "
		    "test won't be started until the other one is stopped.\n");
		exit(EXIT_FAILURE);
	}

	if (nanomq_conf == NULL) {
		if ((nanomq_conf = nng_zalloc(sizeof(conf))) == NULL) {
			fprintf(stderr,
			    "Cannot allocate storge for configuration, "
			    "quit\n");
			exit(EXIT_FAILURE);
		}

		conf_init(nanomq_conf);
		read_env_conf(nanomq_conf);
	}

	if (nanomq_conf->enable) {
		if (nanomq_conf->tcp_list.count == 0) {
			nanomq_conf->url = nanomq_conf->url != NULL
			    ? nanomq_conf->url
			    : nng_strdup(CONF_TCP_URL_DEFAULT);
		}
	}

	if (nanomq_conf->tls.enable) {
		if (nanomq_conf->tls_list.count == 0) {
			nanomq_conf->tls.url = nanomq_conf->tls.url != NULL
			    ? nanomq_conf->tls.url
			    : nng_strdup(CONF_TLS_URL_DEFAULT);
		}
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
	// check if daemonlize
#ifdef NANO_PLATFORM_WINDOWS
	if (nanomq_conf->daemon) {
		log_error("Daemon mode is not supported on Windows");
		broker_start_rc = -1;
	}
#else
	if (nanomq_conf->daemon == true && process_daemonize()) {
		log_error("Error occurs, cannot daemonize");
		broker_start_rc = -1;
	}
#endif

#if defined(ENABLE_LOG)
	if ((rc = log_init(&nanomq_conf->log)) != 0) {
		NANO_NNG_FATAL("log_init", rc);
	}
#endif
	print_conf(nanomq_conf);

#if !defined(BUILD_APP_LIB)
	if (store_pid()) {
		log_error("create \"nanomq.pid\" file failed");
	}
#endif

	// TODO: more check for arg nanomq_conf?
	rc = broker(nanomq_conf);
	
	broker_start_rc = rc == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
	return NULL;
}

#if (!defined(NANO_PLATFORM_WINDOWS) && !defined(BUILD_APP_LIB))

int
broker_stop(int argc, char **argv)
{
	int pid = 0;

	if (argc > 2) {
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
broker_reload(int argc, char **argv)
{
	int pid = 0;
	if (status_check(&pid) != 0) {
		fprintf(stderr,
		    "NanoMQ is not running, use command "
		    "'nanomq start [--conf <path>]' to start a new instance."
		    "\n");
		exit(EXIT_FAILURE);
	}

	conf *nanomq_conf;

	if ((nanomq_conf = nng_zalloc(sizeof(conf))) == NULL) {
		fprintf(stderr,
		    "Cannot allocate storge for configuration, quit\n");
		exit(EXIT_FAILURE);
	}

	conf_init(nanomq_conf);

	int rc = file_path_parse(argc, argv, &nanomq_conf->conf_file);
	if (!rc) {
		fprintf(stderr, "Cannot parse command line arguments, quit\n");
		exit(EXIT_FAILURE);
	}

	if (nanomq_conf->conf_file == NULL) {
		nanomq_conf->conf_file = CONF_PATH_NAME;
		printf("Config file is not specified, use default config "
		       "file: %s\n",
		    nanomq_conf->conf_file);
	}

	conf_parse_ver2(nanomq_conf);
	char *msg = encode_client_cmd(nanomq_conf->conf_file, rc);

	char *cmd_ipc_url = nanomq_conf->hook_ipc_url == NULL
	    ? CMD_IPC_URL
	    : nanomq_conf->cmd_ipc_url;
	start_cmd_client(msg, cmd_ipc_url);

	if (msg) {
		nng_strfree(msg);
	}

	conf_fini(nanomq_conf);

	return 0;
}

int
broker_restart(int argc, char **argv)
{
	int pid = 0;

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
	log_error("Not support on Windows or App lib\n");
	exit(EXIT_SUCCESS);
}

int
broker_reload(int argc, char **argv)
{
	conf *nanomq_conf;

	if ((nanomq_conf = nng_zalloc(sizeof(conf))) == NULL) {
		fprintf(stderr,
		    "Cannot allocate storge for configuration, quit\n");
		exit(EXIT_FAILURE);
	}

	conf_init(nanomq_conf);

	int rc = file_path_parse(argc, argv, &nanomq_conf->conf_file);
	if (!rc) {
		fprintf(stderr, "Cannot parse command line arguments, quit\n");
		exit(EXIT_FAILURE);
	}

	if (nanomq_conf->conf_file == NULL) {
		nanomq_conf->conf_file = CONF_PATH_NAME;
		printf("Config file is not specified, use default config "
		       "file: %s\n",
		    nanomq_conf->conf_file);
	}

	conf_parse_ver2(nanomq_conf);

	char *msg = encode_client_cmd(nanomq_conf->conf_file, rc);
	char *cmd_ipc_url = nanomq_conf->hook_ipc_url == NULL
	    ? CMD_IPC_URL
	    : nanomq_conf->cmd_ipc_url;

	start_cmd_client(msg, cmd_ipc_url);

	if (msg) {
		nng_strfree(msg);
	}

	conf_fini(nanomq_conf);

	return 0;
}

int
broker_stop(int argc, char **argv)
{
	log_error("Not support on Windows or App lib\n");
	exit(EXIT_SUCCESS);
}

#endif

int
broker_dflt(int argc, char **argv)
{
	print_usage();
	return 0;
}
