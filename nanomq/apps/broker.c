//
// Copyright 2021 NanoMQ Team, Inc. <jaylin@emqx.io>
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
#include <syslog.h>
#include <unistd.h>

#include <conf.h>
#include <hash.h>
#include <mqtt_db.h>
#include <nng.h>
#include <nng/mqtt/mqtt_client.h>
#include <protocol/mqtt/mqtt_parser.h>
#include <protocol/mqtt/nmq_mqtt.h>
#include <zmalloc.h>

#include "include/bridge.h"
#include "include/nanomq.h"
#include "include/process.h"
#include "include/pub_handler.h"
#include "include/sub_handler.h"
#include "include/unsub_handler.h"
#include "include/web_server.h"

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
	nng_msg *  msg;
	nng_msg *  smsg = NULL;
	int        rv;

	reason_code reason;
	uint8_t *   ptr;
	conn_param *cparam = NULL;

	struct pipe_info p_info;

	switch (work->state) {
	case INIT:
		debug_msg("INIT ^^^^ ctx%d ^^^^\n", work->ctx.id);
		if (work->proto == 0x01) {
			work->state = BRIDGE;
		} else {
			work->state = RECV;
		}
	    nng_ctx_recv(work->ctx, work->aio);
		break;
	case RECV:
		debug_msg("RECV  ^^^^ ctx%d ^^^^\n", work->ctx.id);
		if ((rv = nng_aio_result(work->aio)) != 0) {
			debug_syslog(
			    "ERROR: RECV nng aio result error: %d", rv);
			nng_aio_wait(work->aio);
			fatal("RECV nng_ctx_recv", rv);
		}
		msg = nng_aio_get_msg(work->aio);
		if (msg == NULL) {
			fatal("RECV NULL MSG", rv);
		}
		work->msg    = msg;
		work->cparam = nng_msg_get_conn_param(work->msg);
		work->pid    = nng_msg_get_pipe(work->msg);

		if (nng_msg_cmd_type(msg) == CMD_DISCONNECT) {
			// Disconnect reserved for will msg.
			if (conn_param_get_will_flag(work->cparam)) {
				msg = nano_msg_composer(&msg,
				    conn_param_get_will_retain(work->cparam),
				    conn_param_get_will_qos(work->cparam),
				    (mqtt_string *) conn_param_get_will_msg(
				        work->cparam),
				    (mqtt_string *) conn_param_get_will_topic(
				        work->cparam));
				nng_msg_set_cmd_type(msg, CMD_PUBLISH);
				work->msg = msg;
				handle_pub(work, work->pipe_ct);
			} else {
				work->msg   = NULL;
				work->state = RECV;
				nng_ctx_recv(work->ctx, work->aio);
				break;
			}
		} else if (nng_msg_cmd_type(msg) == CMD_PUBLISH || nni_msg_get_type(msg) == CMD_PUBLISH) {
			nng_msg_set_timestamp(msg, nng_clock());
			nng_msg_set_cmd_type(msg, CMD_PUBLISH);
			handle_pub(work, work->pipe_ct);

			conf_bridge *bridge = work->bridge;
			if (bridge->bridge_mode) {
				bool found = false;
				for (size_t i = 0; i < bridge->forwards_count;
				     i++) {
					if (topic_filter(bridge->forwards[i],
					        work->pub_packet
					            ->variable_header.publish
					            .topic_name.body)) {
						found = true;
						break;
					}
				}

				if (found) {
					client_publish(work->bridge_sock,
					    work->pub_packet->variable_header
					        .publish.topic_name.body,
					    work->pub_packet->payload_body
					        .payload,
					    work->pub_packet->payload_body
					        .payload_len,
					    work->pub_packet->fixed_header.dup,
					    work->pub_packet->fixed_header.qos,
					    work->pub_packet->fixed_header
					        .retain);
				}
			}
		} else if (nng_msg_cmd_type(msg) == CMD_CONNACK) {
			nng_msg_set_pipe(work->msg, work->pid);

			if (work->cparam != NULL) {
				conn_param_clone(
				    work->cparam); // avoid being free
			}
			// restore clean session
			char *clientid =
			    (char *) conn_param_get_clientid(work->cparam);
			if (clientid != NULL) {
				restore_session(clientid, work->cparam,
				    work->pid.id, work->db);
			}

			// clone for sending connect event notification
			nng_msg_clone(work->msg);
			nng_aio_set_msg(work->aio, work->msg);
			nng_ctx_send(work->ctx, work->aio); // send connack

			uint8_t *header = nng_msg_header(work->msg);
			uint8_t  flag   = *(header + 3);
			smsg = nano_msg_notify_connect(work->cparam, flag);

			nng_msg_set_cmd_type(smsg, CMD_PUBLISH);
			nng_msg_free(work->msg);
			work->msg = smsg;
			handle_pub(work, work->pipe_ct);

			// Free here due to the clone before
			conn_param_free(work->cparam);

			work->state = WAIT;
			nng_aio_finish(work->aio, 0);
			break;
		} else if (nng_msg_cmd_type(msg) == CMD_DISCONNECT_EV) {
			nng_msg_set_cmd_type(work->msg, CMD_PUBLISH);
			handle_pub(work, work->pipe_ct);
			// cache session
			client_ctx *cli_ctx = NULL;
			char *      clientid =
			    (char *) conn_param_get_clientid(work->cparam);
			if (clientid != NULL &&
			    conn_param_get_clean_start(work->cparam) == 0) {
				cache_session(clientid, work->cparam,
				    work->pid.id, work->db);
			}
			// free client ctx
			if (check_id(work->pid.id)) {
				topic_queue *tq = get_topic(work->pid.id);
				while (tq) {
					if (tq->topic) {
						cli_ctx = dbtree_delete_client(
						    work->db, tq->topic, 0,
						    work->pid.id);
					}
					del_sub_ctx(cli_ctx, tq->topic);
					tq = tq->next;
				}
				del_topic_all(work->pid.id);
			} else {
				debug_msg("ERROR it should not happen");
			}
			cparam       = work->cparam;
			work->cparam = NULL;
			conn_param_free(cparam);
		}
		work->state = WAIT;
		nng_aio_finish(work->aio, 0);
		// nng_aio_finish_sync(work->aio, 0);
		break;
	case WAIT:
		debug_msg("WAIT ^^^^ ctx%d ^^^^", work->ctx.id);
		if (nng_msg_cmd_type(work->msg) == CMD_PINGREQ) {
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
		} else if (nng_msg_cmd_type(work->msg) == CMD_SUBSCRIBE) {
			nng_msg_alloc(&smsg, 0);
			work->pid     = nng_msg_get_pipe(work->msg);
			work->sub_pkt = nng_alloc(sizeof(packet_subscribe));
			if (work->sub_pkt == NULL) {
				debug_msg("ERROR: nng_alloc");
			}
			if ((reason = decode_sub_message(work)) != SUCCESS ||
			    (reason = sub_ctx_handle(work)) != SUCCESS ||
			    (reason = encode_suback_message(smsg, work)) !=
			        SUCCESS) {
				debug_msg("ERROR: sub_handler: [%d]", reason);
				if (check_id(work->pid.id)) {
					del_topic_all(work->pid.id);
				}
			} else {
				// success but check info
				debug_msg("sub_pkt:"
				          " pktid: [%d]"
				          " topicLen: [%d]"
				          " topic: [%s]",
				    work->sub_pkt->packet_id,
				    work->sub_pkt->node->it->topic_filter.len,
				    work->sub_pkt->node->it->topic_filter
				        .body);
				debug_msg("suback:"
				          " headerLen: [%ld]"
				          " bodyLen: [%ld]"
				          " type: [%x]"
				          " len:[%x]"
				          " pakcetid: [%x %x].",
				    nng_msg_header_len(smsg),
				    nng_msg_len(smsg),
				    *((uint8_t *) nng_msg_header(smsg)),
				    *((uint8_t *) nng_msg_header(smsg) + 1),
				    *((uint8_t *) nng_msg_body(smsg)),
				    *((uint8_t *) nng_msg_body(smsg) + 1));
			}
			nng_msg_free(work->msg);
			destroy_sub_pkt(work->sub_pkt, conn_param_get_protover(work->cparam));
			// handle retain
			if (work->msg_ret) {
				debug_msg("retain msg [%p] size [%ld] \n",
				    work->msg_ret,
				    cvector_size(work->msg_ret));
				for (int i = 0;
				     i < cvector_size(work->msg_ret); i++) {
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
			work->msg = smsg;
			nng_msg_set_pipe(work->msg, work->pid);
			nng_aio_set_msg(work->aio, work->msg);
			work->msg   = NULL;
			work->state = SEND;
			nng_ctx_send(work->ctx, work->aio);
			smsg = NULL;
			nng_aio_finish(work->aio, 0);
			break;
		} else if (nng_msg_cmd_type(work->msg) == CMD_UNSUBSCRIBE) {
			nng_msg_alloc(&smsg, 0);
			work->unsub_pkt =
			    nng_alloc(sizeof(packet_unsubscribe));
			work->pid = nng_msg_get_pipe(work->msg);
			if (work->unsub_pkt == NULL) {
				debug_msg("ERROR: nng_alloc");
			}
			if ((reason = decode_unsub_message(work)) != SUCCESS ||
			    (reason = unsub_ctx_handle(work)) != SUCCESS ||
			    (reason = encode_unsuback_message(smsg, work)) !=
			        SUCCESS) {
				debug_msg("ERROR: unsub_handler [%d]", reason);
			} else {
				// success but check info
				debug_msg("unsub_pkt:"
				          " pktid: [%d]"
				          " topicLen: [%d]",
				    work->unsub_pkt->packet_id,
				    work->unsub_pkt->node->it->topic_filter
				        .len);
				debug_msg("unsuback:"
				          " headerLen: [%ld]"
				          " bodyLen: [%ld]."
				          " bodyType: [%x]"
				          " len: [%x]"
				          " packetid: [%x %x].",
				    nng_msg_header_len(smsg),
				    nng_msg_len(smsg),
				    *((uint8_t *) nng_msg_header(smsg)),
				    *((uint8_t *) nng_msg_header(smsg) + 1),
				    *((uint8_t *) nng_msg_body(smsg)),
				    *((uint8_t *) nng_msg_body(smsg) + 1));
			}
			// free unsub_pkt
			destroy_unsub_ctx(work->unsub_pkt);
			nng_msg_free(work->msg);

			work->msg    = smsg;
			work->pid.id = 0;
			nng_msg_set_pipe(work->msg, work->pid);
			nng_aio_set_msg(work->aio, work->msg);
			work->msg   = NULL;
			work->state = SEND;
			nng_ctx_send(work->ctx, work->aio);
			smsg = NULL;
			nng_aio_finish(work->aio, 0);
			break;
		} else if (nng_msg_cmd_type(work->msg) == CMD_PUBLISH) {
			if ((rv = nng_aio_result(work->aio)) != 0) {
				debug_msg("WAIT nng aio result error: %d", rv);
				fatal("WAIT nng_ctx_recv/send", rv);
			}
			smsg      = work->msg; // reuse the same msg
			work->msg = NULL;

			debug_msg("total pipes: %d", work->pipe_ct->total);
			// TODO rewrite this part.
			if (work->pipe_ct->total > 0) {
				p_info = work->pipe_ct->pipe_info
				             [work->pipe_ct->current_index];
				work->pipe_ct->encode_msg(smsg, p_info.work,
				    p_info.cmd, p_info.qos, 0);
				while (work->pipe_ct->total >
				    work->pipe_ct->current_index) {
					p_info =
					    work->pipe_ct->pipe_info
					        [work->pipe_ct->current_index];
					nng_msg_clone(smsg);
					work->msg = smsg;

					nng_aio_set_prov_extra(work->aio, 0,
					    (void *) (intptr_t) p_info.qos);
					nng_aio_set_msg(work->aio, work->msg);
					work->pid.id = p_info.pipe;
					nng_msg_set_pipe(work->msg, work->pid);
					work->msg = NULL;
					work->pipe_ct->current_index++;
					nng_ctx_send(work->ctx, work->aio);
				}
				if (work->pipe_ct->total <=
				    work->pipe_ct->current_index) {
					free_pub_packet(work->pub_packet);
					free_pipes_info(
					    work->pipe_ct->pipe_info);
					init_pipe_content(work->pipe_ct);
				}
				work->state = SEND;
				nng_msg_free(smsg);
				smsg        = NULL;
				nng_aio_finish(work->aio, 0);
				break;
			} else {
				if (smsg) {
					nng_msg_free(smsg);
				}
				free_pub_packet(work->pub_packet);
				free_pipes_info(work->pipe_ct->pipe_info);
				init_pipe_content(work->pipe_ct);
			}

			if (work->state != SEND) {
				if (work->msg != NULL)
					nng_msg_free(work->msg);
				work->msg = NULL;

				if (work->proto == 0x01) {
					work->state = BRIDGE;
				} else {
					work->state = RECV;
				}
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
			fatal("nng_recv_aio", rv);
			work->state = RECV;
			nng_ctx_recv(work->ctx, work->aio);
			break;
		}
	    work->msg   = nng_aio_get_msg(work->aio);
		msg = work->msg;
		uint32_t payload_len;
		uint8_t *payload =
		    nng_mqtt_msg_get_publish_payload(msg, &payload_len);
		uint32_t    topic_len;
		const char *recv_topic =
		    nng_mqtt_msg_get_publish_topic(msg, &topic_len);

		bool dup    = nng_mqtt_msg_get_publish_dup(msg);
		bool qos    = nng_mqtt_msg_get_publish_qos(msg);
		bool retain = nng_mqtt_msg_get_publish_retain(msg);

		char *send_topic = nng_alloc(topic_len);
		memcpy(send_topic, recv_topic, topic_len);

		nng_free(send_topic, topic_len);

		// nng_msg_free(msg);
        nng_msg_set_cmd_type(msg, nni_msg_get_type(msg));
		work->msg   = msg;
		work->state = RECV;
		nng_aio_finish(work->aio, 0);
        break;
	case SEND:
		if (NULL != smsg) {
			smsg = NULL;
		}
		if ((rv = nng_aio_result(work->aio)) != 0) {
			debug_msg("SEND nng aio result error: %d", rv);
			fatal("SEND nng_ctx_send", rv);
		}
		if (work->pipe_ct->total > 0) {
			free_pub_packet(work->pub_packet);
			free_pipes_info(work->pipe_ct->pipe_info);
			init_pipe_content(work->pipe_ct);
		}
		work->msg   = NULL;
		if (work->proto == 0x01) {
			work->state = BRIDGE;
		} else {
            work->state = RECV;
		}
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
	if ((rv = nng_mtx_alloc(&w->mutex)) != 0) {
		fatal("nng_mtx_alloc", rv);
	}
	w->pipe_ct = nng_alloc(sizeof(struct pipe_content));
	init_pipe_content(w->pipe_ct);

	w->state = INIT;
	return (w);
}

static dbtree *db     = NULL;
static dbtree *db_ret = NULL;

dbtree *
get_broker_db(void)
{
	return db;
}

static inline void
proto_work_init(nano_work *work, uint8_t proto, nng_socket sock)
{
    work              = alloc_work(sock);
	work->db          = db;
	work->db_ret      = db_ret;
	work->proto       = proto;
    work->bridge_sock = sock;
}

int
broker(conf *nanomq_conf)
{
	nng_socket   sock;

	nng_socket bridge_sock;
	nng_pipe     pipe_id;
	int          rv;
	int          i;
	// add the num of other proto
	uint64_t    num_ctx;
	const char *url = nanomq_conf->url;
	num_ctx         = nanomq_conf->parallel + 1;
	struct work *works[num_ctx];

	// init tree
	dbtree_create(&db);
	if (db == NULL) {
		debug_msg("NNL_ERROR error in db create");
	}
	dbtree_create(&db_ret);
	if (db_ret == NULL) {
		debug_msg("NNL_ERROR error in db create");
	}

	/*  Create the socket. */
	nanomq_conf->db_root = db;
	sock.id              = 0;
	sock.data            = nanomq_conf;
	rv                   = nng_nmq_tcp0_open(&sock);
	if (rv != 0) {
		fatal("nng_nmq_tcp0_open", rv);
	}


	if (nanomq_conf->bridge.bridge_mode) {
        	nng_socket bridge_sock;
		bridge_client(
		    &bridge_sock, num_ctx, &nanomq_conf->bridge);
        // bridge_client(&bridge_sock,  "mqtt-tcp://192.168.23.105:1885", 1);
	}

	for (i = 0; i < nanomq_conf->parallel; i++) {
		works[i]              = alloc_work(sock);
		works[i]->db          = db;
		works[i]->db_ret      = db_ret;
		works[i]->proto       = 0;
		works[i]->bridge_sock = bridge_sock;
		works[i]->bridge      = &nanomq_conf->bridge;
        //check conf
		works[i]->bridge_sock = bridge_sock;
	}
    works[num_ctx-1]              = alloc_work(bridge_sock);
	works[num_ctx-1]->db          = db;
	works[num_ctx-1]->db_ret      = db_ret;
	works[num_ctx-1]->proto       = 0x01;
	works[num_ctx-1]->bridge_sock = bridge_sock;
    //TODO replace it with proto_work_init

	if ((rv = nng_listen(sock, url, NULL, 0)) != 0) {
		fatal("nng_listen", rv);
	}

	// read from command line & config file
	if (nanomq_conf->websocket.enable) {

		if (nanomq_conf->websocket.url == NULL) {
			nanomq_conf->websocket.url = WEBSOCKET_URL;
		}
		if ((rv = nng_listen(
		         sock, nanomq_conf->websocket.url, NULL, 0)) != 0) {
			fatal("nng_listen websocket", rv);
		}
	}

	for (i = 0; i < num_ctx; i++) {
		server_cb(works[i]); // this starts them going (INIT state)
	}

#if (defined DEBUG) && (defined ASAN)
	signal(SIGINT, intHandler);
	for (;;) {
		if (keepRunning == 0) {
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
	fprintf(stderr, USAGE);
}

int
status_check(pid_t *pid)
{
	char * data = NULL;
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
}

int
store_pid()
{
	int  status;
	char pid_c[10] = "";

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
	conf_init(&nanomq_conf);

	for (i = 0; i < argc; i++, temp = 0) {
		if (!strcmp("-conf", argv[i])) {
			debug_msg("reading user specified nanomq conf file:%s",
			    argv[i + 1]);
			conf_path = argv[++i];
		} else if (!strcmp("-bridge", argv[i])) {
			debug_msg("reading user specified bridge conf file:%s",
			    argv[i + 1]);
			bridge_conf_path = argv[++i];
		} else if (!strcmp("-daemon", argv[i])) {
			nanomq_conf->daemon = true;
		} else if (!strcmp("-tq_thread", argv[i]) &&
		    ((i + 1) < argc) && isdigit(argv[++i][0]) &&
		    ((temp = atoi(argv[i])) > 0) && (temp < 256)) {
			nanomq_conf->num_taskq_thread = temp;
		} else if (!strcmp("-max_tq_thread", argv[i]) &&
		    ((i + 1) < argc) && isdigit(argv[++i][0]) &&
		    ((temp = atoi(argv[i])) > 0) && (temp < 256)) {
			nanomq_conf->max_taskq_thread = temp;
		} else if (!strcmp("-parallel", argv[i]) && ((i + 1) < argc) &&
		    isdigit(argv[++i][0]) && ((temp = atoi(argv[i])) > 0)) {
			nanomq_conf->parallel = temp;
		} else if (!strcmp("-property_size", argv[i]) &&
		    ((i + 1) < argc) && isdigit(argv[++i][0]) &&
		    ((temp = atoi(argv[i])) > 0)) {
			nanomq_conf->property_size = temp;
		} else if (!strcmp("-msq_len", argv[i]) && ((i + 1) < argc) &&
		    isdigit(argv[++i][0]) && ((temp = atoi(argv[i])) > 0)) {
			nanomq_conf->msq_len = temp;
		} else if (!strcmp("-qos_duration", argv[i]) &&
		    ((i + 1) < argc) && isdigit(argv[++i][0]) &&
		    ((temp = atoi(argv[i])) > 0)) {
			nanomq_conf->qos_duration = temp;
		} else if (!strcmp("-url", argv[i])) {
			if (nanomq_conf->url != NULL) {
				zfree(nanomq_conf->url);
			}
			nanomq_conf->url = argv[++i];
		} else if (!strcmp("-http", argv[i])) {
			nanomq_conf->http_server.enable = true;
		} else if (!strcmp("-port", argv[i]) && ((i + 1) < argc) &&
		    isdigit(argv[++i][0]) && ((temp = atoi(argv[i])) > 0) &&
		    (temp < 65536)) {
			nanomq_conf->http_server.port = temp;
		} else {
			fprintf(stderr,
			    "Invalid command line arugment input, "
			    "nanomq broker terminates\n");
			print_usage();
			exit(EXIT_FAILURE);
		}
	}

	conf_parser(&nanomq_conf, conf_path);
	conf_bridge_parse(nanomq_conf, bridge_conf_path);

	if (nanomq_conf->url == NULL) {
		fprintf(stderr,
		    "INFO: invalid input url, using default url: %s\n"
		    "Set the url by editing nanomq.conf "
		    "or command-line (-url <url>).\n",
		    CONF_URL_DEFAULT);
		nanomq_conf->url = CONF_URL_DEFAULT;
	}

	print_conf(nanomq_conf);
	print_bridge_conf(&nanomq_conf->bridge);

	active_conf(nanomq_conf);

	if (nanomq_conf->http_server.enable) {
		start_rest_server(nanomq_conf);
	}

	if (store_pid()) {
		debug_msg("create \"nanomq.pid\" file failed");
	}

	rc = broker(nanomq_conf);

	if (nanomq_conf->http_server.enable) {
		stop_rest_server();
	}
	exit(rc == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
}

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

	if (argc < 1) {
		print_usage();
		exit(EXIT_FAILURE);
	}

	if (!(status_check(&pid))) {
		kill(pid, SIGTERM);
		while (!status_check(&pid)) {
			kill(pid, SIGKILL);
		}
		fprintf(stderr, "Previous NanoMQ instance stopped.\n");
	} else {
		fprintf(stderr, "There is no running NanoMQ instance.\n");
	}

	broker_start(argc, argv);
}

int
broker_dflt(int argc, char **argv)
{
	print_usage();
	return 0;
}
