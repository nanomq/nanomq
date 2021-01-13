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

#include <nng.h>
#include <mqtt_db.h>
#include <msg_pool.h>
#include <hash.h>
#include <zmalloc.h>
#include <protocol/mqtt/nano_tcp.h>
#include <protocol/mqtt/mqtt_parser.h>

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
#ifndef PARALLEL
#define PARALLEL 32
#endif

// The server keeps a list of work items, sorted by expiration time,
// so that we can use this to set the timeout to the correct value for
// use in poll.

void
fatal(const char *func, int rv)
{
	fprintf(stderr, "%s: %s\n", func, nng_strerror(rv));
	exit(1);
}

void
server_cb(void *arg)
{
	emq_work *work = arg;
	nng_msg  *msg;
	nng_msg  *smsg = NULL, *tmsg = NULL;
	nng_pipe pipe;
	int      rv, i;

	reason_code reason;
	uint8_t     buf[2];

	struct pipe_info p_info;

	switch (work->state) {
		case INIT:
			debug_msg("INIT ^^^^^^^^^^^^^^^^^^^^^ ctx%d ^^^^\n", work->ctx.id);
			work->state = RECV;
			nng_ctx_recv(work->ctx, work->aio);
			break;
		case RECV:
			debug_msg("RECV  ^^^^^^^^^^^^^^^^^^^^^ ctx%d ^^^^\n", work->ctx.id);
			if (smsg != NULL) {
				if (nng_msg_refcnt(smsg) > 1) {
					nng_msg_free(smsg);
				} else {
					nnl_msg_put(work->msg_pool, &smsg);
				}
				smsg = NULL;
			}
			if ((rv = nng_aio_result(work->aio)) != 0) {
				debug_msg("ERROR: RECV nng aio result error: %d", rv);
				nng_aio_wait(work->aio);
				//break;
				fatal("RECV nng_ctx_recv", rv);
			}
			msg     = nng_aio_get_msg(work->aio);
			if (msg == NULL) {
				debug_msg("ERROR: RECV NULL msg");
				fatal("RECV NULL MSG", rv);
			}
			pipe = nng_msg_get_pipe(msg);

			if (nng_msg_cmd_type(msg) == CMD_DISCONNECT) {
				work->cparam = (conn_param *) nng_msg_get_conn_param(msg);
				char   *clientid = (char *) conn_param_get_clentid(work->cparam);
				struct topic_and_node tan;
				struct client         *cli      = NULL;
				struct topic_queue    *tq       = NULL;

				debug_msg("##########DISCONNECT (clientID:[%s])##########", clientid);
				if (check_id(clientid)) {
					tq = get_topic(clientid);
					while (tq) {
						if (tq->topic) {
							char **topics = topic_parse(tq->topic);
							search_node(work->db, topics, &tan);
							free_topic_queue(topics);
							if ((cli      = del_client(&tan, clientid)) == NULL) {
								break;
							}
						}
						if (cli) {
							del_node(tan.node);
							debug_msg("destroy ctx: [%p] clientid: [%s]", cli->ctxt, cli->id);
							// TODO free client_ctx rather than work->sub_ctx / pub_pkt?
							del_sub_ctx(cli->ctxt, tq->topic); // only free work->sub_pkt
							nng_free(cli, sizeof(struct client));
						}
						tq = tq->next;
					}
				}
				del_sub_client_id(clientid);
				del_sub_pipe_id(pipe.id);
				destroy_conn_param(work->cparam);

				work->state = RECV;
				if (nng_msg_refcnt(msg) > 1) {
					nng_msg_free(msg);
				} else {
					nnl_msg_put(work->msg_pool, &msg);
				}
				work->msg = NULL;
				nng_ctx_recv(work->ctx, work->aio);
				break;
			}

			work->msg   = msg;
			work->state = WAIT;
			debug_msg("RECV ********************* msg: %x*****************\n",
			          nng_msg_cmd_type(work->msg));
            nng_aio_finish(work->aio, 0);
            //nng_aio_finish_sync(work->aio, 0);
			break;
		case WAIT:
			debug_msg("WAIT ^^^^^^^^^^^^^^^^^^^^^ ctx%d ^^^^", work->ctx.id);
			// We could add more data to the message here.
			work->msg = nng_aio_get_msg(work->aio);
			work->cparam = nng_msg_get_conn_param(work->msg);
			if (nng_msg_cmd_type(work->msg) == CMD_PINGREQ) {
				if (work->msg != NULL){
					if (nng_msg_refcnt(msg) > 1) {
						nng_msg_free(msg);
					} else {
						nnl_msg_put(work->msg_pool, &msg);
					}
				}
				work->msg   = NULL;
				work->state = RECV;
				nng_ctx_recv(work->ctx, work->aio);
				break;
			} else if (nng_msg_cmd_type(work->msg) == CMD_SUBSCRIBE) {
				nnl_msg_get(work->msg_pool, &smsg);
				work->pid = nng_msg_get_pipe(work->msg);
				struct client_ctx * cli_ctx;
				if ((cli_ctx = nng_alloc(sizeof(client_ctx))) == NULL) {
					debug_msg("ERROR: nng_alloc");
				}
				work->sub_pkt = nng_alloc(sizeof(packet_subscribe));
				if (work->sub_pkt == NULL) {
					debug_msg("ERROR: nng_alloc");
				}
				if ((reason = decode_sub_message(work))          != SUCCESS ||
				    (reason = sub_ctx_handle(work, cli_ctx))     != SUCCESS ||
				    (reason = encode_suback_message(smsg, work)) != SUCCESS) {
					debug_msg("ERROR: sub_handler: [%d]", reason);

					destroy_sub_ctx(cli_ctx);
					del_sub_pipe_id(work->pid.id);
					del_sub_client_id((char *)conn_param_get_clentid(work->cparam));
				} else {
					// success but check info
					debug_msg("sub_pkt:"
						" pktid: [%d]"
						" topicLen: [%d]"
						" topic: [%s]",
						work->sub_pkt->packet_id,
						work->sub_pkt->node->it->topic_filter.len,
						work->sub_pkt->node->it->topic_filter.body);
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
				nng_msg_set_cmd_type(smsg, CMD_SUBACK);
				nnl_msg_put(work->msg_pool, &work->msg);

				work->msg = smsg;
				nng_aio_set_msg(work->aio, work->msg);
				work->msg   = NULL;
				work->state = SEND;
				nng_ctx_send(work->ctx, work->aio);
				smsg = NULL;
				nng_aio_finish(work->aio, 0);
				break;
			} else if (nng_msg_cmd_type(work->msg) == CMD_UNSUBSCRIBE) {
				nnl_msg_get(work->msg_pool, &smsg);
				work->unsub_pkt = nng_alloc(sizeof(packet_unsubscribe));
				if (work->unsub_pkt == NULL) {
					debug_msg("ERROR: nng_alloc");
				}
				if ((reason = decode_unsub_message(work))          != SUCCESS ||
				    (reason = unsub_ctx_handle(work))              != SUCCESS ||
				    (reason = encode_unsuback_message(smsg, work)) != SUCCESS) {
					debug_msg("ERROR: unsub_handler [%d]", reason);
				} else {
					// success but check info
					debug_msg("unsub_pkt:"
						" pktid: [%d]"
						" topicLen: [%d]",
						work->unsub_pkt->packet_id,
						work->unsub_pkt->node->it->topic_filter.len);
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
				nnl_msg_put(work->msg_pool, &work->msg);

				work->msg = smsg;
				// We could add more data to the message here.
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
				nnl_msg_get(work->msg_pool, &smsg);

				work->pid = nng_msg_get_pipe(work->msg);
				handle_pub(work, work->pipe_ct);
				if (nng_msg_refcnt(work->msg) > 1) {
					nng_msg_free(work->msg);
				} else {
					nnl_msg_put(work->msg_pool, &work->msg);
				}

                debug_msg("total pipes: %d", work->pipe_ct->total);
				//TODO rewrite this part.
				if (work->pipe_ct->total > 0) {
					p_info = work->pipe_ct->pipe_info[work->pipe_ct->current_index];
					work->pipe_ct->encode_msg(smsg, p_info.work, p_info.cmd, p_info.qos, 0);

					while(work->pipe_ct->total > work->pipe_ct->current_index){
						p_info = work->pipe_ct->pipe_info[work->pipe_ct->current_index];
						nng_msg_clone(smsg);
						work->msg = smsg;
						nng_aio_set_msg(work->aio, work->msg);
						work->msg = NULL;

						if (p_info.pipe != 0 /*&& p_info.pipe != work->pid.id*/) {
							nng_aio_set_pipeline(work->aio, p_info.pipe);
						}

						work->state = SEND;
						work->pipe_ct->current_index++;
						nng_ctx_send(work->ctx, work->aio);
					}
					if (work->pipe_ct->total <= work->pipe_ct->current_index) {
						free_pub_packet(work->pub_packet);
						free_pipes_info(work->pipe_ct->pipe_info);
						init_pipe_content(work->pipe_ct);
					}
					work->state = SEND;
					if (nng_msg_refcnt(smsg) > 1) {
						nng_msg_free(smsg);
					} else {
						nnl_msg_put(work->msg_pool, &smsg);
					}
					nng_aio_finish(work->aio, 0);
					break;
				} else {
					free_pub_packet(work->pub_packet);
					free_pipes_info(work->pipe_ct->pipe_info);
					init_pipe_content(work->pipe_ct);
				}

				if (work->state != SEND) {
					if (work->msg != NULL) {
						nnl_msg_put(work->msg_pool, &work->msg);
					}
					work->msg   = NULL;
					work->state = RECV;
					nng_ctx_recv(work->ctx, work->aio);
				}
			} else if (nng_msg_cmd_type(work->msg) == CMD_PUBACK ||
					   nng_msg_cmd_type(work->msg) == CMD_PUBREC ||
					   nng_msg_cmd_type(work->msg) == CMD_PUBREL ||
					   nng_msg_cmd_type(work->msg) == CMD_PUBCOMP ) {
				if (nng_msg_refcnt(work->msg) > 1) {
					nng_msg_free(work->msg);
				} else {
					nnl_msg_put(work->msg_pool, &work->msg);
				}
				work->msg   = NULL;
				work->state = RECV;
				nng_ctx_recv(work->ctx, work->aio);
				break;
			} else {
				debug_msg("broker has nothing to do");
				if (work->msg != NULL) {
					if (nng_msg_refcnt(work->msg) > 1) {
						nng_msg_free(work->msg);
					} else {
						nnl_msg_put(work->msg_pool, &work->msg);
					}
				}
				work->msg   = NULL;
				work->state = RECV;
				nng_ctx_recv(work->ctx, work->aio);
				break;
			}
			break;

		case SEND:
			debug_msg("SEND  ^^^^^^^^^^^^^^^^^^^^^ ctx%d ^^^^\n", work->ctx.id);
			if (NULL != smsg) {
				if (nng_msg_refcnt(smsg) > 1) {
					nng_msg_free(smsg);
				} else {
					nnl_msg_put(work->msg_pool, &smsg);
				}
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
	int         rv;

	if ((w  = nng_alloc(sizeof(*w))) == NULL) {
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
int
broker(const char *url)
{
	nng_socket     sock;
	nng_pipe       pipe_id;
	struct work    *works[PARALLEL];
	int            rv;
	int            i;
	// init tree
	struct db_tree *db = NULL;
	nnl_msg_pool * msg_pool = NULL;

	create_db_tree(&db);
	rv = nnl_msg_pool_create(&msg_pool);
	if (rv != 0) fatal("msg_pool create error.", rv);

	/*  Create the socket. */
	rv = nng_nano_tcp0_open(&sock);
	if (rv != 0) {
		fatal("nng_nano_tcp0_open", rv);
	}

	//TODO will be dynamic in the future
	debug_msg("PARALLEL logic threads: %d\n", PARALLEL);
	for (i = 0; i < PARALLEL; i++) {
		works[i] = alloc_work(sock);
		works[i]->db = db;
		works[i]->msg_pool = msg_pool;
		nng_aio_set_dbtree(works[i]->aio, db);
		nng_aio_set_msg_pool(works[i]->aio, msg_pool);
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
	rc = broker(argv[0]);
	exit(rc == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
}

int broker_dflt(int argc, char **argv)
{
	debug_msg("i dont know what to do here yet");
	return 0;
}
