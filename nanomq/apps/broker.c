//
// Copyright 2020 NanoMQ Team, Inc. <jaylin@emqx.io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <protocol/mqtt/mqtt_parser.h>
#include <nng.h>
#include <mqtt_db.h>
#include <hash.h>
#include <zmalloc.h>

#include "include/nanomq.h"
#include "include/pub_handler.h"
#include "include/sub_handler.h"
#include "include/unsub_handler.h"

// Parallel is the maximum number of outstanding requests we can handle.
// This is *NOT* the number of threads in use, but instead represents
// outstanding work items.  Select a small number to reduce memory size.
// (Each one of these can be thought of as a request-reply loop.)  Note
// that you will probably run into limitations on the number of open file
// descriptors if you set this too high. (If not for that limit, this could
// be set in the thousands, each context consumes a couple of KB.)
// #ifndef PARALLEL
// #define PARALLEL 128
// #endif
#define PARALLEL 64

// The server keeps a list of work items, sorted by expiration time,
// so that we can use this to set the timeout to the correct value for
// use in poll.

void
fatal(const char *func, int rv)
{
	fprintf(stderr, "%s: %s\n", func, nng_strerror(rv));
	exit(1);
}

/*objective: 1 input/output low latency
	     2 KV
	     3 tree 
*/
void
server_cb(void *arg)
{
	emq_work *work = arg;
	nng_ctx  ctx2;
	nng_msg  *msg;
	nng_msg  *smsg;
	nng_pipe pipe;
	int      rv;
	uint32_t when;

	reason_code reason;
	uint8_t     buf[2];

	switch (work->state) {
		case INIT:
			debug_msg("INIT ^^^^^^^^^^^^^^^^^^^^^ \n");
			work->state = RECV;
			nng_ctx_recv(work->ctx, work->aio);
			debug_msg("INIT!!\n");
			break;
		case RECV:
			debug_msg("RECV  ^^^^^^^^^^^^^^^^^^^^^ %d ^^^^\n", work->ctx.id);
			if ((rv = nng_aio_result(work->aio)) != 0) {
				debug_msg("ERROR: RECV nng aio result error: %d", rv);
				nng_aio_wait(work->aio);
				//break;
				fatal("RECV nng_ctx_recv", rv);
			}
			msg     = nng_aio_get_msg(work->aio);
			if (msg == NULL) {        //BUG
				debug_msg("ERROR: RECV NULL msg");
				//fatal("RECV NULL MSG", rv);
			}
			pipe = nng_msg_get_pipe(msg);
			debug_msg("RECVIED %d %x\n", work->ctx.id, nng_msg_cmd_type(msg));

			if (nng_msg_cmd_type(msg) == CMD_DISCONNECT) {
				work->cparam = (conn_param *) nng_msg_get_conn_param(msg);
				char                  *clientid = (char *) conn_param_get_clentid(work->cparam);
				struct topic_and_node tan;
				struct client         *cli      = NULL;
				struct topic_queue    *tq       = NULL;

				debug_msg("##########DISCONNECT (clientID:[%s])##########", clientid);
				if (check_id(clientid)) {
					tq                         = get_topic(clientid);
					while (tq) {
						if (tq->topic) {
							char ** topics = topic_parse(tq->topic);
							search_node(work->db, topics, &tan);
							free_topic_queue(topics);
							if ((cli = del_client(&tan, clientid)) == NULL) {
								break;
							}
						}
						if (cli) {
							del_node(tan.node);
							debug_msg("Destroy CTX [%p] clientID: [%s]", cli->ctxt, cli->id);
							destroy_sub_ctx(cli->ctxt, tq->topic); // only free work->sub_pkt
							nng_free(cli, sizeof(struct client));
						}
						tq = tq->next;
						/*
						if (check_id(clientid)) {
							tq = tq->next;
						}
						*/
					}
					debug_msg("INHASH: clientid [%s] exist?: [%d]; pipeid [%d] exist?: [%d]",
					          clientid, (int) check_id(clientid), pipe.id, (int) check_pipe_id(pipe.id));
				}

				del_topic_all(clientid);
				del_pipe_id(pipe.id);

				work->state = RECV;
				nng_msg_free(msg);
				work->msg = NULL;
				nng_aio_abort(work->aio, 31);
				nng_ctx_recv(work->ctx, work->aio);
				break;
			}

			work->msg   = msg;
			work->state = WAIT;
			debug_msg("RECV ********************* msg: %s %x******************************************\n",
			          (char *) nng_msg_body(work->msg), nng_msg_cmd_type(work->msg));
			nng_sleep_aio(100, work->aio);
			break;
		case WAIT:
			debug_msg("WAIT ^^^^^^^^^^^^^^^^^^^^^ %d ^^^^", work->ctx.id);
			// We could add more data to the message here.
			work->cparam = (conn_param *) nng_msg_get_conn_param(work->msg);
			//debug_msg("WAIT   %x %s %d pipe: %d\n", nng_msg_cmd_type(work->msg),
			//conn_param_get_clentid(work->cparam), work->ctx.id, work->pid.id);
/*
        if ((rv = nng_msg_append_u32(msg, msec)) != 0) {
                fatal("nng_msg_append_u32", rv);
        }
*/
			//reply to client if needed. nng_send_aio vs nng_sendmsg? async or sync? BETTER sync due to realtime requirement
			//TODO
			if ((rv = nng_msg_alloc(&smsg, 0)) != 0) {
				debug_msg("error nng_msg_alloc^^^^^^^^^^^^^^^^^^^^^");
			}
			if (nng_msg_cmd_type(work->msg) == CMD_PINGREQ) {
				buf[0] = CMD_PINGRESP;
				buf[1] = 0x00;
				debug_msg("reply PINGRESP\n");

				if ((rv = nng_msg_header_append(smsg, buf, 2)) != 0) {
					debug_msg("error nng_msg_append^^^^^^^^^^^^^^^^^^^^^");
				}
				nng_msg_free(work->msg);
				work->msg = smsg;
				// We could add more data to the message here.
				nng_aio_set_msg(work->aio, work->msg);

				work->msg   = NULL;
				work->state = SEND;
				nng_ctx_send(work->ctx, work->aio);
				break;

			} else if (nng_msg_cmd_type(work->msg) == CMD_SUBSCRIBE) {
				pipe = nng_msg_get_pipe(work->msg);
				work->pid = pipe;
				debug_msg("get pipe!!  ^^^^^^^^^^^^^^^^^^^^^ %d %d\n", pipe.id, work->pid.id);
				work->sub_pkt = nng_alloc(sizeof(struct packet_subscribe));
				if ((reason = decode_sub_message(work->msg, work->sub_pkt)) != SUCCESS ||
				    (reason = sub_ctx_handle(work)) != SUCCESS ||
				    (reason = encode_suback_message(smsg, work->sub_pkt)) != SUCCESS) {
					debug_msg("ERROR IN SUB_HANDLE: %d", reason);
					destroy_sub_ctx(work, "");
				} else {
					// success but check info
					debug_msg("In sub_pkt: pktid:%d, topicLen: %d, topic: %s", work->sub_pkt->packet_id,
					          work->sub_pkt->node->it->topic_filter.len,
					          work->sub_pkt->node->it->topic_filter.str_body);
					debug_msg("SUBACK: Header Len: %ld, Body Len: %ld. In Body. TYPE:%x LEN:%x PKTID: %x %x.",
					          nng_msg_header_len(smsg), nng_msg_len(smsg), *((uint8_t *) nng_msg_header(smsg)),
					          *((uint8_t *) nng_msg_header(smsg) + 1), *((uint8_t *) nng_msg_body(smsg)),
					          *((uint8_t *) nng_msg_body(smsg) + 1));
				}
				nng_msg_free(work->msg);

				work->msg = smsg;
				// We could add more data to the message here.
				nng_aio_set_msg(work->aio, work->msg);
				work->msg   = NULL;
				work->state = SEND;
				nng_ctx_send(work->ctx, work->aio);
				break;
				//nng_send_aio
			} else if (nng_msg_cmd_type(work->msg) == CMD_UNSUBSCRIBE) {
				work->unsub_pkt = nng_alloc(sizeof(struct packet_unsubscribe));
				if ((reason = decode_unsub_message(work->msg, work->unsub_pkt)) != SUCCESS ||
				    (reason = unsub_ctx_handle(work)) != SUCCESS ||
				    (reason = encode_unsuback_message(smsg, work->unsub_pkt)) != SUCCESS) {
					debug_msg("ERROR IN UNSUB_HANDLE: %d", reason);
					// TODO free unsub_pkt
				} else {
					// check info
					debug_msg("In unsub_pkt: pktid:%d, topicLen: %d", work->unsub_pkt->packet_id,
					          work->unsub_pkt->node->it->topic_filter.len);
					debug_msg("Header Len: %ld, Body Len: %ld.", nng_msg_header_len(smsg), nng_msg_len(smsg));
					debug_msg("In Body. TYPE:%x LEN:%x PKTID: %x %x.", *((uint8_t *) nng_msg_header(smsg)),
					          *((uint8_t *) nng_msg_header(smsg) + 1), *((uint8_t *) nng_msg_body(smsg)),
					          *((uint8_t *) nng_msg_body(smsg) + 1));
				}
				nng_msg_free(work->msg);

				work->msg = smsg;
				// We could add more data to the message here.
				nng_aio_set_msg(work->aio, work->msg);
				work->msg   = NULL;
				work->state = SEND;
				nng_ctx_send(work->ctx, work->aio);
				break;
			} else if (nng_msg_cmd_type(work->msg) == CMD_PUBLISH ||
			           nng_msg_cmd_type(work->msg) == CMD_PUBACK ||
			           nng_msg_cmd_type(work->msg) == CMD_PUBREC ||
			           nng_msg_cmd_type(work->msg) == CMD_PUBREL ||
			           nng_msg_cmd_type(work->msg) == CMD_PUBCOMP) {

//				nng_mtx_lock(work->mutex);

				if ((rv = nng_aio_result(work->aio)) != 0) {
					debug_msg("WAIT nng aio result error: %d", rv);
					fatal("WAIT nng_ctx_recv/send", rv);
					//nng_aio_wait(work->aio);
					//break;
				}
				handle_pub(work, smsg);
				nng_msg_free(work->msg);
/*
				char **topic_queue = NULL;
				topic_queue = topic_parse("A/B/C");
				search_client(work->db->root, topic_queue);
				zfree(*topic_queue);
				zfree(topic_queue);
				nng_msg_free(work->msg);

*/
				if (work->pipe_ct->total > 0) {
					debug_msg("set pipeline[%d]: [%d], current pipeline: [%d]",
					          work->pipe_ct->pipe_msg[work->pipe_ct->current_index].index,
					          work->pipe_ct->pipe_msg[work->pipe_ct->current_index].pipe, work->pid.id);

					work->msg = work->pipe_ct->pipe_msg[work->pipe_ct->current_index].msg;
					nng_aio_set_msg(work->aio, work->msg);
					work->msg   = NULL;
					work->state = SEND;

					if (work->pipe_ct->pipe_msg[work->pipe_ct->current_index].pipe != work->pid.id) {
						nng_aio_set_pipeline(work->aio, work->pipe_ct->pipe_msg[work->pipe_ct->current_index].pipe);
					}

					work->pipe_ct->current_index++;
					if (work->pipe_ct->total == work->pipe_ct->current_index) {
						free(work->pipe_ct->pipe_msg);
						init_pipe_content(work->pipe_ct);
					}

					nng_msg_free(smsg);
					nng_ctx_send(work->ctx, work->aio);
					break;
				}

				if (work->state != SEND) {
					nng_msg_free(smsg);
					if (work->msg != NULL) {
						nng_msg_free(work->msg);
					}

					work->msg   = NULL;
					work->state = RECV;
					nng_ctx_recv(work->ctx, work->aio);
				}
//				nng_mtx_unlock(work->mutex);

			} else {
				debug_msg("broker has nothing to do");
				if (smsg != NULL) {
					nng_msg_free(smsg);
				}
				if (work->msg != NULL) {
					nng_msg_free(work->msg);
				}
				work->msg   = NULL;
				work->state = RECV;
				nng_ctx_recv(work->ctx, work->aio);
				break;
			}
			break;

		case SEND:
			debug_msg("SEND  ^^^^^^^^^^^^^^^^^^^^^ %d ^^^^\n", work->ctx.id);
			if ((rv = nng_aio_result(work->aio)) != 0) {
				debug_msg("SEND nng aio result error: %d", rv);
				fatal("SEND nng_ctx_send", rv);
			} else if ((smsg = nng_aio_get_msg(work->aio)) != NULL) {
				nng_msg_free(smsg);
			}

			if (work->pipe_ct->total > work->pipe_ct->current_index) {
				debug_msg("set pipeline[%d]: [%d]", work->pipe_ct->pipe_msg[work->pipe_ct->current_index].index,
				          work->pipe_ct->pipe_msg[work->pipe_ct->current_index].pipe);

				work->msg = work->pipe_ct->pipe_msg[work->pipe_ct->current_index].msg;
				nng_aio_set_msg(work->aio, work->msg);
				work->msg   = NULL;
				work->state = SEND;
				if (work->pipe_ct->pipe_msg[work->pipe_ct->current_index].pipe != 0 &&
				    work->pipe_ct->pipe_msg[work->pipe_ct->current_index].pipe != work->pid.id) {
					nng_aio_set_pipeline(work->aio, work->pipe_ct->pipe_msg[work->pipe_ct->current_index].pipe);
				}

				work->pipe_ct->current_index++;
				if (work->pipe_ct->total == work->pipe_ct->current_index) {
					free(work->pipe_ct->pipe_msg);
					init_pipe_content(work->pipe_ct);
				}

				nng_ctx_send(work->ctx, work->aio);
			} else {
				work->msg   = NULL;
				work->state = RECV;
				nng_ctx_recv(work->ctx, work->aio);
			}
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
	int         rv;

	if ((w  = nng_alloc(sizeof(*w))) == NULL) {
		fatal("nng_alloc", NNG_ENOMEM);
	}
	if ((rv = nng_aio_alloc(&w->aio, server_cb, w)) != 0) {
		fatal("nng_aio_alloc", rv);
	}
	//not pipe id; max id = uint32_t
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

// The server runs forever.
int
server(const char *url)
{
	nng_socket     sock;
	nng_pipe       pipe_id;
	struct work    *works[PARALLEL];
	int            rv;
	int            i;
	// init tree
	struct db_tree *db = NULL;
	create_db_tree(&db);

	/*  Create the socket. */
	rv = nng_nano_tcp0_open(&sock);
	if (rv != 0) {
		fatal("nng_nano_tcp0_open", rv);
	}

	debug_msg("PARALLEL: %d\n", PARALLEL);
	for (i = 0; i < PARALLEL; i++) {
		works[i] = alloc_work(sock);
		works[i]->db = db;
		nng_aio_set_dbtree(works[i]->aio, db);
//		works[i]->pid = pipe_id;
	}

	if ((rv = nng_listen(sock, url, NULL, 0)) != 0) {
		fatal("nng_listen", rv);
	}

	for (i = 0; i < PARALLEL; i++) {
		server_cb(works[i]); // this starts them going (INIT state)
	}

	for (;;) {
		nng_msleep(3600000); // neither pause() nor sleep() portable
	}
}

int broker_start(int argc, char **argv)
{
	int rc;
	if (argc != 1) {
		fprintf(stderr, "Usage: broker start <url>\n");
		exit(EXIT_FAILURE);
	}
	rc = server(argv[0]);
	exit(rc == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
}

int broker_dflt(int argc, char **argv)
{
	debug_msg("i dont know what to do here yet");
	return 0;
}
