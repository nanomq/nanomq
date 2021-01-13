//
// Copyright 2020 NanoMQ Team, Inc. <jaylin@emqx.io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <string.h>
#include <mqtt_db.h>
#include <msg_pool.h>
#include <hash.h>

#include "core/nng_impl.h"
#include "nng/protocol/mqtt/nano_tcp.h"
#include "nng/protocol/mqtt/mqtt_parser.h"

#include "nng/protocol/mqtt/mqtt.h"
//TODO rewrite as nano_mq protocol with RPC support

typedef struct nano_pipe nano_pipe;
typedef struct nano_sock nano_sock;
typedef struct nano_ctx  nano_ctx;

static void nano_ctx_timeout(void *);
static void nano_pipe_send_cb(void *);
static void nano_pipe_recv_cb(void *);
static void nano_pipe_fini(void *);
static void nano_pipe_timeout(void *);
static void nano_pipe_qos_timeout(void *);
static void nano_pipe_close(void *);
//static void nano_period_check(nano_sock *s, nni_list *sent_list, void *arg);
static void nano_keepalive(nano_pipe *p, void *arg);
static void nano_qos_msg_repack(nni_msg *msg, nano_pipe *p);

//huge context/ dynamic context?
struct nano_ctx {
	nano_sock *    sock;
	uint32_t       pipe_id;
	//uint32_t      resend_count;
	//uint32_t      pipe_len;	//record total length of pipe_id queue when resending
	nano_pipe *    spipe, * qos_pipe; // send pipe
	nni_aio *      saio;  // send aio
	nni_aio *      raio;  // recv aio
	//uint32_t*     rspipes;// pub resend pipe queue Qos 1/2
	//nni_list      send_queue; // contexts waiting to send.
	nni_list_node  sqnode;
	nni_list_node  rqnode;
	nni_msg *      rmsg;
    nni_msg *      smsg;
	nni_timer_node qos_timer;
};

// nano_sock is our per-socket protocol private structure.
struct nano_sock {
	nni_mtx        lk;
	nni_atomic_int ttl;
	nni_id_map     pipes;
	nni_list       recvpipes; // list of pipes with data to receive
	nni_list       recvq;
	nano_ctx       ctx;		//base socket
	nni_pollable   readable;
	nni_pollable   writable;
};

// nano_pipe is our per-pipe protocol private structure.
struct nano_pipe {
	nni_pipe *      pipe;
	nni_id_map      nano_db;
	nni_id_map      retain_db; // hash clientid->lmq[msg ptr1...N]
	nano_sock *     rep;
	uint32_t        id;
	void *          tree;	//root node of db tree
	nni_aio         aio_send;
	nni_aio         aio_recv;
	nni_list_node   rnode; // receivable list linkage
	nni_list        sendq; // contexts waiting to send
	bool            busy;
	bool            closed;
    bool            ka_refresh;
    uint8_t         qos_retry;      //for marking qos retry type
    conn_param *    conn_param;
	nano_pipe_db *  pipedb_root;
    nni_lmq         qlmq, rlmq;
    nni_timer_node  ka_timer;
    nni_timer_node  pipe_qos_timer;
	nnl_msg_pool *  msg_pool;
};
/*
static void
nano_period_check(nano_sock *s, nni_list *sent_list, void *arg)
{
    nano_ctx *ctx;
	nni_aio * aio;
    debug_msg("periodcal task over");
}
*/

static void
nano_keepalive(nano_pipe *p, void *arg)
{
    uint16_t     interval;

    interval = conn_param_get_keepalive(p->conn_param);
    debug_msg("KeepAlive: %d", interval);
    //20% KeepAlive as buffer time for multi-threading
    nni_timer_schedule(&p->ka_timer, nni_clock() + NNI_SECOND * interval * 0.8);
}

static void
nano_ctx_timeout(void *arg)
{
	nano_ctx  * ctx = arg;
	nano_sock * s   = ctx->sock;
    nano_pipe * p   = ctx->qos_pipe;
    nni_msg   * msg = ctx->smsg;

	nni_mtx_lock(&s->lk);
    debug_msg("************* ctx timeout triggered! %x %p %s *************", nni_msg_cmd_type(msg), ctx, nni_msg_body(msg));
    p->busy = true;
    //len     = nni_msg_len(msg);
    nni_aio_set_msg(&p->aio_send, msg);
    nni_pipe_send(p->pipe, &p->aio_send);
    //nni_timer_schedule(&ctx->qos_timer, nni_clock() + NNI_SECOND * 8);
	nni_mtx_unlock(&s->lk);
}

static void
nano_ctx_close(void *arg)
{
	nano_ctx * ctx = arg;
	nano_sock *s   = ctx->sock;
	nni_aio *  aio;

	debug_msg("nano_ctx_close");
	nni_mtx_lock(&s->lk);
	if ((aio = ctx->saio) != NULL) {
		//nano_pipe *pipe = ctx->spipe;
		ctx->saio       = NULL;
		ctx->spipe      = NULL;
        ctx->qos_pipe   = NULL;
		ctx->rmsg	= NULL;
		//nni_list_remove(&pipe->sendq, ctx);
		nni_aio_finish_error(aio, NNG_ECLOSED);
	}
	if ((aio = ctx->raio) != NULL) {
		nni_list_remove(&s->recvq, ctx);
		ctx->raio = NULL;
		nni_aio_finish_error(aio, NNG_ECLOSED);
	}
	nni_mtx_unlock(&s->lk);
}

static void
nano_ctx_fini(void *arg)
{
	nano_ctx *ctx = arg;

	nano_ctx_close(ctx);

    //timer
    debug_msg("========= nano_ctx_fini =========");
    nni_timer_cancel(&ctx->qos_timer);
	nni_timer_fini(&ctx->qos_timer);
}

static int
nano_ctx_init(void *carg, void *sarg)
{
	nano_sock *s   = sarg;
	nano_ctx * ctx = carg;

	debug_msg("&&&&&&&& nano_ctx_init %p &&&&&&&&&", ctx);
	NNI_LIST_NODE_INIT(&ctx->sqnode);
	NNI_LIST_NODE_INIT(&ctx->rqnode);

    nni_timer_init(&ctx->qos_timer, nano_ctx_timeout, ctx);
	//TODO send list??
	//ctx->pp_len = 0;
	ctx->sock       = s;
	ctx->pipe_id    = 0;

	return (0);
}

static void
nano_ctx_cancel_send(nni_aio *aio, void *arg, int rv)
{
	nano_ctx * ctx = arg;
	nano_sock *s   = ctx->sock;

    debug_msg("*********** nano_ctx_cancel_send ***********");
	nni_mtx_lock(&s->lk);
	if (ctx->saio != aio) {
		nni_mtx_unlock(&s->lk);
		return;
	}
	nni_list_node_remove(&ctx->sqnode);
	ctx->saio = NULL;
	nni_mtx_unlock(&s->lk);

	nni_msg_header_clear(nni_aio_get_msg(aio)); // reset the headers
	nni_aio_finish_error(aio, rv);
}

static void
nano_ctx_send(void *arg, nni_aio *aio)
{
	nano_ctx     *ctx = arg;
	nano_sock    *s   = ctx->sock;
	nano_pipe    *p;
	nni_msg      *msg;
	int           rv;
	size_t        len;
	uint32_t      pipe;
	nnl_msg_pool *msg_pool;
	//uint32_t   p_id[2],i = 0,fail_count = 0, need_resend = 0;

	msg = nni_aio_get_msg(aio);
	msg_pool = (nnl_msg_pool *)nni_aio_get_msg_pool(aio);

	if (nni_aio_begin(aio) != 0) {
		return;
	}

	debug_msg("############### nano_ctx_send with ctx %p msg type %x ###############",
              ctx, nni_msg_cmd_type(msg));
	nni_mtx_lock(&s->lk);

	if ((pipe = nni_aio_get_pipeline(aio)) != 0){
		nni_aio_set_pipeline(aio, 0);
	} else {
		pipe = ctx->pipe_id;   //reply to self
	}

	//ctx->pp_len = 0;
	ctx->pipe_id    = 0;		//ensure PING/DISCONNECT/PUBACK only sends once

	if (ctx == &s->ctx) {
		//in prototype, we only send once in each sock.
		nni_pollable_clear(&s->writable);
	}

	len     = nni_msg_len(msg);
	debug_msg("*************************** working with pipe id : %d ctx***************************", pipe);
	if ((p = nni_id_get(&s->pipes, pipe)) == NULL) {
		// Pipe is gone.  Make this look like a good send to avoid
		// disrupting the state machine.  We don't care if the peer
		// lost interest in our reply.
		nni_mtx_unlock(&s->lk);
		nni_aio_set_msg(aio, NULL);
		//nni_aio_finish(aio, 0, nni_msg_len(msg));
		while (nni_msg_refcnt(msg) > 1) {
			nni_msg_free(msg);
		}
		nnl_msg_put(msg_pool, &msg);
		return;
	}

	// TODO should be init in other function
	p->msg_pool = msg_pool;
	p->tree     = nni_aio_get_dbtree(aio);

    if (nni_msg_cmd_type(msg) == CMD_PUBLISH) {
		nano_qos_msg_repack(msg, p);
    	if (nni_msg_get_pub_qos(msg) > 0) {
        	debug_msg("******** processing QoS pubmsg with pipe: %p ********", p);
        	p->qos_retry = 0;
        	nni_msg_clone(msg);
			if (nni_lmq_full(&p->qlmq)) {
				// Make space for the new message.
         		debug_msg("Warning: QoS message dropped");
                //printf("Warning: QoS message dropped\n");
				nni_msg *old1;
				(void) nni_lmq_getq(&p->qlmq, &old1);
				if (nng_msg_refcnt(old1) > 1) {
					nni_msg_free(old1);
				} else {
					nnl_msg_put(msg_pool, &old1);
				}
			}
			nni_lmq_putq(&p->qlmq, msg);
    	}
    }

	if (!p->busy) {
		p->busy = true;
		nni_aio_set_msg(&p->aio_send, msg);
		nni_pipe_send(p->pipe, &p->aio_send);
		nni_mtx_unlock(&s->lk);

		nni_aio_set_msg(aio, NULL);
		//nni_aio_finish(aio, 0, len);
		return;
	}

	if ((rv = nni_aio_schedule(aio, nano_ctx_cancel_send, ctx)) != 0) {
		nni_mtx_unlock(&s->lk);
		//nni_aio_finish_error(aio, rv);
		return;
	}
	debug_msg("WARNING: pipe %d occupied! resending in cb!", pipe);
	//printf("WARNING: pipe %d occupied! resending in cb!\n", pipe);
    if (nni_lmq_full(&p->rlmq)) {
        // Make space for the new message.
		debug_msg("warning msg dropped!");
		printf("warning msg dropped!\n");
        nni_msg *old;
        (void) nni_lmq_getq(&p->rlmq, &old);
		if (nng_msg_refcnt(old) > 1) {
			nni_msg_free(old);
		} else {
			nnl_msg_put(msg_pool, &old);
		}
    }
    nni_lmq_putq(&p->rlmq, msg);

	nni_mtx_unlock(&s->lk);
    nni_aio_set_msg(aio, NULL);
	return;
    //nni_aio_finish(aio, 0, len);        //AIO Finish here?
}

static void
nano_sock_fini(void *arg)
{
	nano_sock *s = arg;

	nni_id_map_fini(&s->pipes);
	nano_ctx_fini(&s->ctx);
	nni_pollable_fini(&s->writable);
	nni_pollable_fini(&s->readable);
	nni_mtx_fini(&s->lk);
}

static int
nano_sock_init(void *arg, nni_sock *sock)
{
	nano_sock *s = arg;

	NNI_ARG_UNUSED(sock);

	nni_mtx_init(&s->lk);

	nni_id_map_init(&s->pipes, 0, 0, false);
	NNI_LIST_INIT(&s->recvq, nano_ctx, rqnode);
	NNI_LIST_INIT(&s->recvpipes, nano_pipe, rnode);

	nni_atomic_init(&s->ttl);
	nni_atomic_set(&s->ttl, 8);

	(void) nano_ctx_init(&s->ctx, s);

    debug_msg("************* nano_sock_init %p *************", s);
	// We start off without being either readable or writable.
	// Readability comes when there is something on the socket.
	nni_pollable_init(&s->writable);
	nni_pollable_init(&s->readable);

	return (0);
}

static void
nano_sock_open(void *arg)
{
	NNI_ARG_UNUSED(arg);
}

static void
nano_sock_close(void *arg)
{
	nano_sock *s = arg;

	nano_ctx_close(&s->ctx);
}

static void
nano_pipe_timeout(void *arg)
{
	nano_pipe * p = arg;
	nano_sock * s = p->rep;
    uint16_t    interval;
    nni_msg   * msg;

    if (!p->ka_refresh) {
        debug_msg("Warning: close pipe & kick client due to KeepAlive timeout!");
        nano_pipe_close(p);
        return;
    }
	nni_mtx_lock(&s->lk);

    //retry rlmq msgs
    if (!p->busy) {
        if (nni_lmq_getq(&p->rlmq, &msg) == 0) {
            p->busy = true;
            nni_aio_set_msg(&p->aio_send, msg);
            //nni_msg_clone(msg);
            debug_msg("rlmq msg resending! %ld msgs left\n", nni_lmq_len(&p->rlmq));
            nni_pipe_send(p->pipe, &p->aio_send);
        }
    }

    p->ka_refresh = false;
    debug_msg("*************** KeepAlive timeout triggered ***************");
    interval = conn_param_get_keepalive(p->conn_param);
    nni_timer_schedule(&p->ka_timer, nni_clock() + NNI_SECOND * interval * 2);
	nni_mtx_unlock(&s->lk);
}

static void
nano_pipe_qos_timeout(void *arg)
{
	nano_pipe * p = arg;
	nano_sock * s = p->rep;
    nni_msg   * m;

	nni_mtx_lock(&s->lk);
    debug_msg("********** pipe_qos timeout triggered **********");

    //TODO check timestamp of each msg, whether send it or not
    if (!p->busy) {
        if (nni_lmq_getq(&p->qlmq, &m) == 0) {
            p->busy = true;
            nni_aio_set_msg(&p->aio_send, m);
            p->qos_retry = 1;
            nni_msg_clone(m);
            nni_pipe_send(p->pipe, &p->aio_send);
        } else {
            debug_msg("Nothing to do, restart the timer");
        }
    }
    nni_timer_schedule(&p->pipe_qos_timer, nni_clock() + NNI_SECOND * NNI_NANO_QOS_TIMER);  //should be configurable
	nni_mtx_unlock(&s->lk);
}

static void
nano_pipe_stop(void *arg)
{
	nano_pipe *p = arg;

    debug_msg("##########nano_pipe_stop###############");
	nni_aio_stop(&p->aio_send);
	nni_aio_stop(&p->aio_recv);
}

static void
nano_pipe_fini(void *arg)
{
	nano_pipe *p = arg;
	nng_msg   *msg;
	nnl_msg_pool *msg_pool;

    debug_msg("##########nano_pipe_fini###############");
	msg_pool = p->msg_pool;

	if ((msg = nni_aio_get_msg(&p->aio_recv)) != NULL) {
		nni_aio_set_msg(&p->aio_recv, NULL);
		msg = nni_msg_unique(msg);
		nnl_msg_put(msg_pool, &msg);
	}

	if ((msg = nni_aio_get_msg(&p->aio_send)) != NULL) {
		nni_aio_set_msg(&p->aio_recv, NULL);
		msg = nni_msg_unique(msg);
		nnl_msg_put(msg_pool, &msg);
	}

	nni_aio_fini(&p->aio_send);
	nni_aio_fini(&p->aio_recv);
	// TODO lmq will nni_msg_free msg, and it should work with nnl_msg_pool
    nni_lmq_fini(&p->qlmq);
	nni_lmq_fini(&p->rlmq);
	nni_id_map_fini(&p->nano_db);

    nni_timer_cancel(&p->ka_timer);
    nni_timer_cancel(&p->pipe_qos_timer);
	nni_timer_fini(&p->ka_timer);
    nni_timer_fini(&p->pipe_qos_timer);
}

static int
nano_pipe_init(void *arg, nni_pipe *pipe, void *s)
{
	nano_pipe *p = arg;

    debug_msg("##########nano_pipe_init###############");

    nni_lmq_init(&p->qlmq, NNI_NANO_MAX_QOS_LEN);
	nni_lmq_init(&p->rlmq, NNI_NANO_MAX_MSQ_LEN);
	nni_aio_init(&p->aio_send, nano_pipe_send_cb, p);
	nni_aio_init(&p->aio_recv, nano_pipe_recv_cb, p);
	nni_id_map_init(&p->nano_db, 0, 0, false);

	//NNI_LIST_INIT(&p->sendq, nano_ctx, sqnode);

	p->id         = nni_pipe_id(pipe);
	p->pipe       = pipe;
	p->rep        = s;
    p->conn_param = nni_pipe_get_conn_param(pipe);
    p->ka_refresh = true;
    p->qos_retry  = 0;

    nni_timer_init(&p->ka_timer, nano_pipe_timeout, p);
    nni_timer_init(&p->pipe_qos_timer, nano_pipe_qos_timeout, p);

	return (0);
}

static int
nano_ctx_set_qsize(void *arg, void *arg2, const void *buf, size_t sz, nni_type t)
{
    nano_ctx  * ctx  = arg;
    nano_sock * sock = ctx->sock;
	nano_pipe * p    = arg2;
	int         val;
	int         rv;

	if ((rv = nni_copyin_int(&val, buf, sz, 1, 8192, t)) != 0) {
		return (rv);
	}

	nni_mtx_lock(&sock->lk);
	if ((rv = nni_lmq_resize(&p->rlmq, (size_t) val)) != 0) {
		nni_mtx_unlock(&sock->lk);
		return (rv);
	}

	nni_mtx_unlock(&sock->lk);
	return (0);
}

static int
nano_pipe_start(void *arg)
{
	nano_pipe *p = arg;
	nano_sock *s = p->rep;
	int        rv;
	//TODO check MQTT protocol version here
	debug_msg("##########nano_pipe_start################");
	/*
	// TODO check peer protocol
	if (nni_pipe_peer(p->pipe) != NNG_NANO_TCP_PEER) {
		// Peer protocol mismatch.
		return (NNG_EPROTO);
	}
	*/
    nni_mtx_lock(&s->lk);
    rv = nni_id_set(&s->pipes, nni_pipe_id(p->pipe), p);
    nni_aio_get_output(&p->aio_recv, 1);
    nano_keepalive(p, NULL);
    nni_mtx_unlock(&s->lk);
    if (rv != 0) {
		return (rv);
	}
	// By definition, we have not received a request yet on this pipe,
	// so it cannot cause us to become writable.
	nni_timer_schedule(&p->pipe_qos_timer, nni_clock() + NNI_SECOND * NNI_NANO_QOS_TIMER);
	nni_pipe_recv(p->pipe, &p->aio_recv);
	return (0);
}

static void
nano_pipe_close(void *arg)
{
	nano_pipe *p = arg;
	nano_sock *s = p->rep;
	nano_ctx * ctx;
	void *     tree;
	char *     client_id = NULL;
	nni_aio   *aio;
	nni_msg   *msg;

	debug_msg("################# nano_pipe_close ##############");
	nni_mtx_lock(&s->lk);
	debug_msg("deleting %d", p->id);
	debug_msg("tree : %p", p->tree);

	if (p->tree != NULL) {
//		del_all(p->id, p->tree);
	}
	if ((client_id = get_client_id(p->id)) != NULL) {
		del_topic_all(client_id);
	}
	if (check_pipe_id(p->id)) {
		del_pipe_id(p->id);
	}
	// TODO free conn_param after one to many pub completed
	// destroy_conn_param(p->conn_param);

	nni_aio_close(&p->aio_send);
	nni_aio_close(&p->aio_recv);

	//nni_mtx_lock(&s->lk);
	p->closed = true;
	if (nni_list_active(&s->recvpipes, p)) {
		// We are no longer "receivable".
		nni_list_remove(&s->recvpipes, p);
	}

	nni_lmq_flush(&p->qlmq);
	nni_lmq_flush(&p->rlmq);
	nano_msg_free_pipedb(p->pipedb_root);

	while ((ctx = nni_list_first(&p->sendq)) != NULL) {
		nni_list_remove(&p->sendq, ctx);
		aio       = ctx->saio;
		ctx->saio = NULL;
		msg       = nni_aio_get_msg(aio);
		nni_aio_set_msg(aio, NULL);
		nni_aio_finish(aio, 0, nni_msg_len(msg));
		if (nni_msg_refcnt(msg) > 1) {
			nni_msg_free(msg);
		} else {
			nnl_msg_put(p->msg_pool, &msg);
		}
	}
	nni_id_remove(&s->pipes, nni_pipe_id(p->pipe));
	nni_mtx_unlock(&s->lk);
}

static void
nano_pipe_send_cb(void *arg)
{
	nano_pipe *p = arg;
	nano_sock *s = p->rep;
	nano_ctx * ctx;
	nni_aio *  aio;
	nni_msg *  msg;
	size_t     len;
	//uint32_t   index = 0;
	//uint32_t * pipes;

	debug_msg("################ nano_pipe_send_cb %d ################", p->id);
	//retry here
	if (nni_aio_result(&p->aio_send) != 0) {
		msg = nni_aio_get_msg(&p->aio_send);
		if (nni_msg_refcnt(msg) > 1) {
			nni_msg_free(msg);
		} else {
			nnl_msg_put(p->msg_pool, &msg);
		}
		nni_aio_set_msg(&p->aio_send, NULL);
		nni_pipe_close(p->pipe);
		return;
	}
	nni_mtx_lock(&s->lk);

    //printf("before : rlmq msg resending! %ld %p \n", nni_lmq_len(&p->rlmq), &p->rlmq);
    if (nni_lmq_getq(&p->rlmq, &msg) == 0) {
        nni_aio_set_msg(&p->aio_send, msg);
        debug_msg("rlmq msg resending! %ld msgs left\n", nni_lmq_len(&p->rlmq));
		//printf("rlmq of %ld msg resending! %ld msgs left\n",p->id, nni_lmq_len(&p->rlmq));
        nni_pipe_send(p->pipe, &p->aio_send);
        nni_mtx_unlock(&s->lk);
        return;
    } else {
        p->busy = false;
    }

    if(p->qos_retry > 0) {
        //TODO check what if there are too much msgs with a busy pipe, could qos retry break ctx cb chain?
        //TODO check timestamp of each msg, whether send it or not
        if (nni_lmq_getq(&p->qlmq, &msg) == 0) {
            p->busy    = true;
			nni_msg_clone(msg);
            nni_aio_set_msg(&p->aio_send, msg);
            debug_msg("Warning: qos msg resending!");
            nni_pipe_send(p->pipe, &p->aio_send);
            //nni_aio_finish_sync(aio, 0, len);
        } else {
            p->busy = false;
            p->qos_retry = 0;
        }
        nni_mtx_unlock(&s->lk);
        debug_msg("nano_pipe_send_cb: end of qos logic ctx : %p", ctx);
        return;
    }
    // Nothing else to send.
    nni_mtx_unlock(&s->lk);
    return;
}

static void
nano_cancel_recv(nni_aio *aio, void *arg, int rv)
{
	nano_ctx * ctx = arg;
	nano_sock *s   = ctx->sock;

    debug_msg("*********** nano_cancel_recv ***********");
	nni_mtx_lock(&s->lk);
	if (ctx->raio == aio) {
		nni_list_remove(&s->recvq, ctx);
		ctx->raio = NULL;
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&s->lk);
}

static void
nano_ctx_recv(void *arg, nni_aio *aio)
{
	nano_ctx * ctx = arg;
	nano_sock *s   = ctx->sock;
	nano_pipe *p;
	//size_t     len;
	nni_msg *  msg;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	debug_msg("nano_ctx_recv start %p", ctx);
	nni_mtx_lock(&s->lk);
	if ((p = nni_list_first(&s->recvpipes)) == NULL) {
		int rv;
		if ((rv = nni_aio_schedule(aio, nano_cancel_recv, ctx)) != 0) {
			nni_mtx_unlock(&s->lk);
			nni_aio_finish_error(aio, rv);
			return;
		}
		if (ctx->raio != NULL) {
			// Cannot have a second receive operation pending.
			// This could be ESTATE, or we could cancel the first
			// with ECANCELED.  We elect the former.
			debug_msg("ERROR: former aio not finish yet");
			nni_mtx_unlock(&s->lk);
			nni_aio_finish_error(aio, NNG_ESTATE);
			return;
		}
		ctx->raio = aio;
		nni_list_append(&s->recvq, ctx);
		nni_mtx_unlock(&s->lk);
		return;
	}
	msg = nni_aio_get_msg(&p->aio_recv);
	nni_aio_set_msg(&p->aio_recv, NULL);
	nni_list_remove(&s->recvpipes, p);
	if (nni_list_empty(&s->recvpipes)) {
		nni_pollable_clear(&s->readable);
	}
	nni_pipe_recv(p->pipe, &p->aio_recv);
	if ((ctx == &s->ctx) && !p->busy) {
		nni_pollable_raise(&s->writable);
	}

	//TODO MQTT 5 property

	ctx->pipe_id    = nni_pipe_id(p->pipe);
	debug_msg("nano_ctx_recv ends %p pipe: %p pipe_id: %d", ctx, p, ctx->pipe_id);
	nni_mtx_unlock(&s->lk);

	nni_aio_set_msg(aio, msg);
	nni_aio_finish(aio, 0, nni_msg_len(msg));
}

static void
nano_pipe_recv_cb(void *arg)
{
	nano_pipe *p = arg;
	nano_sock *s = p->rep;
	nano_ctx  *    ctx;
	nni_msg   *    msg;
	uint8_t   *    header;
	nni_aio   *    aio;
	nano_pipe_db * pipe_db;
	size_t         len, index;
	int			   rv;
	//int        hops;
	//int        ttl;

	if (nni_aio_result(&p->aio_recv) != 0) {
		nni_pipe_close(p->pipe);
		return;
	}
	debug_msg("#########nano_pipe_recv_cb !############");

	msg = nni_aio_get_msg(&p->aio_recv);
	if (msg == NULL) {
		goto drop;
	}

	header = nng_msg_header(msg);
	debug_msg("start nano_pipe_recv_cb pipe: %p p_id %d TYPE: %x ===== header: %x %x header len: %zu\n",
              p ,p->id, nng_msg_cmd_type(msg), *header, *(header+1), nng_msg_header_len(msg));
	//ttl = nni_atomic_get(&s->ttl);
	nni_msg_set_pipe(msg, p->id);
    p->ka_refresh = true;
	nni_mtx_lock(&s->lk);
	//TODO HOOK
	switch (nng_msg_cmd_type(msg)) {
		case CMD_SUBSCRIBE:
			//TODO put hash table to tcp layer
			pipe_db = nano_msg_get_subtopic(msg);	//potential memleak when sub failed
			p->pipedb_root = pipe_db;
			while (pipe_db) {
				rv = nni_id_set(&p->nano_db, DJBHash(pipe_db->topic), pipe_db);
				pipe_db = pipe_db->next;
			}
			break;
		case CMD_PUBLISH:
			break;
		case CMD_DISCONNECT:
			break;
		case CMD_PUBREL:
			goto drop;
			break;
		case CMD_UNSUBSCRIBE:
			break;
		case CMD_PINGREQ:
			goto drop;
			break;
		case CMD_PUBCOMP:
			goto drop;
			break;
        case CMD_PUBACK:
		case CMD_PUBREC:
            debug_msg("puback received!");
            uint8_t *ptr;
            uint16_t ackid, pubid;
            nni_msg *lmq_msg;
            //TODO Attention! go thru lmq will disorder qos pub msg
            len = nni_lmq_len(&p->qlmq);
            index = 0;
            while(nni_lmq_getq(&p->qlmq, &lmq_msg) == 0 && index <= len) {
                ptr = nni_msg_variable_ptr(msg);
                NNI_GET16(ptr, ackid);
                ptr = nni_msg_variable_ptr(lmq_msg);
                NNI_GET16(ptr, pubid);
                ptr = ptr + 2 + pubid;
                NNI_GET16(ptr, pubid);
                debug_msg("%d %d", pubid, ackid);
                if(pubid != ackid) {
                    (void) nni_lmq_putq(&p->qlmq, lmq_msg);
                } else {
                    debug_msg("Found ACK msg packet id: %d deleting msg", ackid);
                    if (nni_msg_refcnt(lmq_msg) > 1) {
                        nni_msg_free(lmq_msg);
                    } else {
                        nnl_msg_put(p->msg_pool, &lmq_msg);
                    }
                    break;
                }
                index++;
            }
            //nanomq sdk
			goto drop;
            break;
		default:
			goto drop;
	}

	if (p->closed) {
		// If we are closed, then we can't return data.
		nni_aio_set_msg(&p->aio_recv, NULL);
		nni_mtx_unlock(&s->lk);
		while (nni_msg_refcnt(msg) > 1) {
			nni_msg_free(msg);
		}
		nnl_msg_put(p->msg_pool, &msg);
		debug_msg("ERROR: pipe is closed abruptly!!");
		return;
	}

	if ((ctx = nni_list_first(&s->recvq)) == NULL) {
		// No one waiting to receive yet, holding pattern.
		nni_list_append(&s->recvpipes, p);
		nni_pollable_raise(&s->readable);
		nni_mtx_unlock(&s->lk);
		debug_msg("ERROR: no ctx found!! create more ctxs!");
		nni_println("ERROR: no ctx found!! create more ctxs!");
        //printf("ERROR: no ctx found!! create more ctxs!\n");
		return;
	}

	nni_list_remove(&s->recvq, ctx);
	aio       = ctx->raio;
	ctx->raio = NULL;
	nni_aio_set_msg(&p->aio_recv, NULL);
	if ((ctx == &s->ctx) && !p->busy) {
		nni_pollable_raise(&s->writable);
	}

	// schedule another receive
	nni_pipe_recv(p->pipe, &p->aio_recv);

	//ctx->pp_len = len;		//TODO Rewrite mqtt header length
	ctx->pipe_id = p->id;		//use pipe id to identify which client
	debug_msg("currently processing pipe_id: %d", p->id);

	nni_mtx_unlock(&s->lk);

	nni_aio_set_msg(aio, msg);
	nni_aio_finish(aio, 0, nni_msg_len(msg));
	debug_msg("end of nano_pipe_recv_cb %p", ctx);
	return;

drop:
	nni_aio_set_msg(&p->aio_recv, NULL);
	nni_pipe_recv(p->pipe, &p->aio_recv);
	nni_mtx_unlock(&s->lk);
	while (nni_msg_refcnt(msg) > 1) {
		nni_msg_free(msg);
	}
	nnl_msg_put(p->msg_pool, &msg);
	debug_msg("Warning:dropping msg");
	return;
}

static int
nano_sock_set_max_ttl(void *arg, const void *buf, size_t sz, nni_opt_type t)
{
	nano_sock *s = arg;
	int        ttl;
	int        rv;

	if ((rv = nni_copyin_int(&ttl, buf, sz, 1, NNI_MAX_MAX_TTL, t)) == 0) {
		nni_atomic_set(&s->ttl, ttl);
	}
	return (rv);
}

static int
nano_sock_get_max_ttl(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	nano_sock *s = arg;

	return (nni_copyout_int(nni_atomic_get(&s->ttl), buf, szp, t));
}

static int
nano_sock_get_sendfd(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	nano_sock *s = arg;
	int        rv;
	int        fd;

	if ((rv = nni_pollable_getfd(&s->writable, &fd)) != 0) {
		return (rv);
	}
	return (nni_copyout_int(fd, buf, szp, t));
}

static int
nano_sock_get_recvfd(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	nano_sock *s = arg;
	int        rv;
	int        fd;

	if ((rv = nni_pollable_getfd(&s->readable, &fd)) != 0) {
		return (rv);
	}

	return (nni_copyout_int(fd, buf, szp, t));
}

static void
nano_sock_send(void *arg, nni_aio *aio)
{
	nano_sock *s = arg;

	nano_ctx_send(&s->ctx, aio);
}

static void
nano_sock_recv(void *arg, nni_aio *aio)
{
	nano_sock *s = arg;

	nano_ctx_recv(&s->ctx, aio);
}

//TODO Move to tcp layer
static void
nano_qos_msg_repack(nni_msg *msg, nano_pipe *p)
{
	uint8_t *body, *header, qos_pub, qos_pac, tmp[4] = {0};
	uint16_t	topic_len, pid;
	size_t	 len, tlen;
	nano_pipe_db *db;
	nni_id_map   *idm;
	//QoS TODO optimize log2(n)
	if (nni_msg_cmd_type(msg) == CMD_PUBLISH) {
		qos_pub = nni_msg_get_preset_qos(msg);
		qos_pac = nni_msg_get_pub_qos(msg);
		body    = nni_msg_body(msg);
		header  = nni_msg_header(msg);
		NNI_GET16(body, tlen);
		idm = &p->nano_db;
		if ((db = nni_id_get(&p->nano_db, DJBHashn(body+2, tlen))) == NULL) {
			return;
		}
		debug_msg("qos_pac %d pub %d sub %d\n", qos_pac, qos_pub, db->qos);
		switch (qos_pub & db->qos) {
			case 0x00:
				if ((db->qos | qos_pub) == 0x03)
					goto qos1;
				if (qos_pub > 0) {
					//set QoS
					*header = *header & 0xF9;
					if (qos_pac > 0) {
						//modify remaining length
						nni_msg_header_chop(msg, nni_msg_header_len(msg) - 1);
						len = put_var_integer(tmp, nni_msg_remaining_len(msg) - 2);
						nni_msg_header_append(msg, tmp, len);
						memcpy(&topic_len, body, 2);
						len = tlen + 4;
						nni_msg_trim(msg, len);
						len = NNI_GET16(body, len);
						nni_msg_insert(msg, db->topic, len);
						nni_msg_insert(msg, &topic_len, 2);
						body = nni_msg_body(msg);
						debug_msg("%x %x %x %x\n", *body, *(body+1), *(body+2), *(body +3));
					}
				}
				break;
			case 0x01:
			case 0x02:
qos1:			if (qos_pub == 1 || db->qos == 1) {
					*header = *header | 0x02;
					*header = *header & 0xFB;
				}
				else
					*header = *header | 0x04;
				if (qos_pac == 0) {
					//modify remaining length 
					nni_msg_header_chop(msg, nni_msg_header_len(msg) - 1);
					len = put_var_integer(tmp, nni_msg_remaining_len(msg));
					nni_msg_header_append(msg, tmp, len);
					//modify variable header
					pid = nni_pipe_inc_packetid(p->pipe);
					NNI_PUT16(&topic_len, pid);
					len = tlen + 2;
					nni_msg_trim(msg, len);
					len = NNI_GET16(body, len);

					nni_msg_insert(msg, &pid, 2);
					nni_msg_insert(msg, db->topic, len);
					nni_msg_insert(msg, &topic_len, 2);
					body = nni_msg_body(msg);
					debug_msg("%x %x %x %x\n", *body, *(body+1), *(body+2), *(body +3));
				} else {
					pid = nni_pipe_inc_packetid(p->pipe);
					body = nni_msg_body(msg);
					len = tlen + 2;
					NNI_PUT16(body+len, pid);
				}
				break;
			default:
				//TODO close pipe
				break;
		}
	}
}

// This is the global protocol structure -- our linkage to the core.
// This should be the only global non-static symbol in this file.
static nni_proto_pipe_ops nano_pipe_ops = {
	.pipe_size  = sizeof(nano_pipe),
	.pipe_init  = nano_pipe_init,
	.pipe_fini  = nano_pipe_fini,
	.pipe_start = nano_pipe_start,
	.pipe_close = nano_pipe_close,
	.pipe_stop  = nano_pipe_stop,
};

static nni_proto_ctx_ops nano_ctx_ops = {
	.ctx_size = sizeof(nano_ctx),
	.ctx_init = nano_ctx_init,
	.ctx_fini = nano_ctx_fini,
	.ctx_send = nano_ctx_send,
	.ctx_recv = nano_ctx_recv,
};

static nni_option nano_sock_options[] = {
	{
	    .o_name = NNG_OPT_MAXTTL,
	    .o_get  = nano_sock_get_max_ttl,
	    .o_set  = nano_sock_set_max_ttl,
	},
	{
	    .o_name = NNG_OPT_RECVFD,
	    .o_get  = nano_sock_get_recvfd,
	},
	{
	    .o_name = NNG_OPT_SENDFD,
	    .o_get  = nano_sock_get_sendfd,
	},
	{
	    .o_name = NULL,
	},
};

static nni_proto_sock_ops nano_sock_ops = {
	.sock_size    = sizeof(nano_sock),
	.sock_init    = nano_sock_init,
	.sock_fini    = nano_sock_fini,
	.sock_open    = nano_sock_open,
	.sock_close   = nano_sock_close,
	.sock_options = nano_sock_options,
	.sock_send    = nano_sock_send,
	.sock_recv    = nano_sock_recv,
};

static nni_proto nano_tcp_proto = {
	.proto_version  = NNI_PROTOCOL_VERSION,
	.proto_self     = { NNG_NANO_TCP_SELF, NNG_NANO_TCP_SELF_NAME },
	.proto_peer     = { NNG_NANO_TCP_PEER, NNG_NANO_TCP_PEER_NAME },
	.proto_flags    = NNI_PROTO_FLAG_SNDRCV,
	.proto_sock_ops = &nano_sock_ops,
	.proto_pipe_ops = &nano_pipe_ops,
	.proto_ctx_ops  = &nano_ctx_ops,
};

int
nng_nano_tcp0_open(nng_socket *sidp)
{
	//TODO Global binary tree init here
	return (nni_proto_open(sidp, &nano_tcp_proto));
}
