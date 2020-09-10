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

#include "core/nng_impl.h"
#include "nng/protocol/mqtt/nano_tcp.h"
#include "include/nng_debug.h"
#include "nng/protocol/mqtt/mqtt.h"
//TODO rewrite as nano_mq protocol with RPC support

typedef struct nano_pipe nano_pipe;
typedef struct nano_sock nano_sock;
typedef struct nano_ctx  nano_ctx;

static void nano_pipe_send_cb(void *);
static void nano_pipe_recv_cb(void *);
static void nano_pipe_fini(void *);

//huge context/ dynamic context?
struct nano_ctx {
	nano_sock *sock;
	uint32_t pipe_id;
	//uint32_t      resend_count;
	//uint32_t      pipe_len;	//record total length of pipe_id queue when resending
	nano_pipe *spipe; // send pipe
	nni_aio   *saio;  // send aio
	nni_aio   *raio;  // recv aio
	//uint32_t*     rspipes;// pub resend pipe queue Qos 1/2
	//nni_list      send_queue; // contexts waiting to send.
	nni_list_node sqnode;
	nni_list_node rqnode;
	nni_msg *rmsg;
	//size_t        pp_len;			//property Header
	//uint32_t      pp[NNI_EMQ_MAX_PROPERTY_SIZE + 1];
};

// nano_sock is our per-socket protocol private structure.
struct nano_sock {
	nni_mtx        lk;
	nni_atomic_int ttl;
	nni_idhash *pipes;
	nni_list     recvpipes; // list of pipes with data to receive
	nni_list     recvq;
	nano_ctx     ctx;        //base socket
	nni_pollable readable;
	nni_pollable writable;
};

// nano_pipe is our per-pipe protocol private structure.
struct nano_pipe {
	nni_pipe  *pipe;
	nano_sock *rep;
	uint32_t id;
	//uint8_t       retry;
	void *tree;    //mqtt_db tree root
	nni_aio       aio_send;
	nni_aio       aio_recv;
	nni_list_node rnode; // receivable list linkage
	nni_list      sendq; // contexts waiting to send
	bool busy;
	bool closed;
};

static void
nano_ctx_close(void *arg)
{
	nano_ctx *ctx = arg;
	nano_sock *s = ctx->sock;
	nni_aio *aio;

	debug_msg("nano_ctx_close");
	nni_mtx_lock(&s->lk);
	if ((aio = ctx->saio) != NULL) {
		nano_pipe *pipe = ctx->spipe;
		ctx->saio  = NULL;
		ctx->spipe = NULL;
		ctx->rmsg  = NULL;
		nni_list_remove(&pipe->sendq, ctx);
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
}

static int
nano_ctx_init(void *carg, void *sarg)
{
	nano_sock *s = sarg;
	nano_ctx *ctx = carg;

	debug_msg("&&&&&&&& nano_ctx_init &&&&&&&&&");
	NNI_LIST_NODE_INIT(&ctx->sqnode);
	NNI_LIST_NODE_INIT(&ctx->rqnode);
	//TODO send list??
	//ctx->pp_len = 0;
	ctx->sock    = s;
	ctx->pipe_id = 0;

	return (0);
}

static void
nano_ctx_cancel_send(nni_aio *aio, void *arg, int rv)
{
	nano_ctx *ctx = arg;
	nano_sock *s = ctx->sock;

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
	nano_ctx *ctx = arg;
	nano_sock *s  = ctx->sock;
	nano_pipe *p;
	nni_msg *msg;
	int      rv;
	size_t   len;
	//uint32_t * pipes; // pipes id
	uint32_t pipe;
	uint32_t p_id[2], i = 0, fail_count = 0, need_resend = 0;

	msg = nni_aio_get_msg(aio);

	if (nni_aio_begin(aio) != 0) {
		return;
	}

	debug_msg("############### nano_ctx_send with ctx %p ###############", ctx);
	nni_mtx_lock(&s->lk);
	//len  = ctx->pp_len;
	//if ((pipes = nni_aio_get_pipeline(aio)) != NULL){
	if ((pipe = nni_aio_get_pipeline(aio)) != 0) {
		nni_aio_set_pipeline(aio, 0);
	} else {
		//p_id[0] = ctx->pipe_id;
		//p_id[1] = 0;
		//pipes = &p_id;
		pipe = ctx->pipe_id;
	}

	//ctx->pp_len = 0;
	ctx->pipe_id = 0;        //ensure PING/DISCONNECT/PUBACK only sends once

	if (ctx == &s->ctx) {
		//in prototype, we only send once in each sock.
		//TODO qos 1/2
		nni_pollable_clear(&s->writable);
	}
	if ((rv = nni_aio_schedule(aio, nano_ctx_cancel_send, ctx)) != 0) {
		nni_mtx_unlock(&s->lk);
		nni_aio_finish_error(aio, rv);
		return;
	}

	/*
	//TODO MQTT 5
	if (len == 0) {
		nni_mtx_unlock(&s->lk);
		debug_msg("length : %d!", len);
		nni_aio_finish_error(aio, NNG_ESTATE);
		return;
	}
	if ((rv = nni_msg_header_append(msg, ctx->property, len)) != 0) {
		nni_mtx_unlock(&s->lk);
		debug_msg("header rv : %d!", rv);
		nni_aio_finish_error(aio, rv);
		return;
	}

	//pub mutiple clients/pipes in single aio/ctx
	while (*(pipes+i) != 0) {
		debug_msg("***************************working with pipe id : %d***************************", *(pipes+i));
		if (nni_idhash_find(s->pipes, *(pipes+i), (void **) &p) != 0) {
			// Pipe is gone.  Make this look like a good send to avoid
			// disrupting the state machine.  We don't care if the peer
			// lost interest in our reply.
			debug_msg("pipe %d is gone sth went wrong!", *(pipes+i));
			i++;
			fail_count++;
			continue;
		}
		p->tree = nni_aio_get_dbtree(aio);		//TODO only set db_tree when reply suback first time
		nni_msg_clone(msg);
		if (!p->busy) {
			uint8_t  *header;
			p->busy = true;
			len     = nni_msg_len(msg);
			header  = nng_msg_header(msg);
			debug_msg("send msg :%s header[0]:%x header[1]:%x msg_len:%d", nng_msg_body(msg),*header,*(header+1),len);
			nni_aio_set_msg(&p->aio_send, msg);
			nni_pipe_send(p->pipe, &p->aio_send);
			*(pipes+i) = 0;
		} else {
			ctx->saio  = aio;
			ctx->spipe = p;
			ctx->rmsg  = msg;
			//save ctx to start another round
			debug_msg("pipe %p jamed!", p);
			if (nni_list_first(&p->sendq) == NULL) {
				//nni_list_append(&p->sendq, ctx);
			}
			need_resend++;
		}
		i++;
	}
	if (fail_count == i) {
		goto exit;
	}

	//as long as one pipe sucess, aio is sucessd. TODO qos1/2 broker need to ensure all aio completed.
	debug_msg("pub/reply total %d resend %d fail %d", i, need_resend, fail_count);
	if (need_resend == 0) {
		nni_mtx_unlock(&s->lk);
		nni_aio_set_msg(aio, NULL);
		debug_msg("send sucessfully ctx %p", ctx);
		nni_aio_finish(aio, 0, len);
		return;
	} else if (nni_list_first(&p->sendq) == NULL) {
		ctx->resend_count = need_resend;
		ctx->pipe_len     = i;
		ctx->rspipes      = pipes;
		nni_list_append(&p->sendq, ctx);
		//goto exit;
	} else {
		debug_msg("message dropped!!");
		nni_mtx_unlock(&s->lk);
		nni_aio_set_msg(aio, NULL);
		nni_aio_finish(aio, 0, len);
		return;
	}
	nni_mtx_unlock(&s->lk);
	return;
exit:
	nni_mtx_unlock(&s->lk);
	nni_aio_set_msg(aio, NULL);
	nni_aio_finish(aio, 0 ,nni_msg_len(msg));
	//nni_aio_finish_error(aio, 0);
	nni_msg_free(msg);
	return;*/

	debug_msg("***************************working with pipe id : %d***************************", pipe);
	if (nni_idhash_find(s->pipes, pipe, (void **) &p) != 0) {
		// Pipe is gone.  Make this look like a good send to avoid
		// disrupting the state machine.  We don't care if the peer
		// lost interest in our reply.
		nni_mtx_unlock(&s->lk);
		nni_aio_set_msg(aio, NULL);
		nni_aio_finish(aio, 0, nni_msg_len(msg));
		nni_msg_free(msg);
		return;
	}
	p->tree = nni_aio_get_dbtree(aio);
	if (!p->busy) {
		p->busy = true;
		len = nni_msg_len(msg);
		nni_aio_set_msg(&p->aio_send, msg);
		nni_pipe_send(p->pipe, &p->aio_send);
		nni_mtx_unlock(&s->lk);

		nni_aio_set_msg(aio, NULL);
		nni_aio_finish(aio, 0, len);
		return;
	}

	debug_msg("pipe %p jamed! resending in cb!", pipe);
	ctx->saio  = aio;
	ctx->spipe = p;
	ctx->rmsg  = msg;
	nni_list_append(&p->sendq, ctx);
	nni_mtx_unlock(&s->lk);
}

static void
nano_sock_fini(void *arg)
{
	nano_sock *s = arg;

	nni_idhash_fini(s->pipes);
	nano_ctx_fini(&s->ctx);
	nni_pollable_fini(&s->writable);
	nni_pollable_fini(&s->readable);
	nni_mtx_fini(&s->lk);
}

static int
nano_sock_init(void *arg, nni_sock *sock)
{
	nano_sock *s = arg;
	int       rv;

	NNI_ARG_UNUSED(sock);

	nni_mtx_init(&s->lk);
	if ((rv = nni_idhash_init(&s->pipes)) != 0) {
		nano_sock_fini(s);
		return (rv);
	}

	NNI_LIST_INIT(&s->recvq, nano_ctx, rqnode);
	NNI_LIST_INIT(&s->recvpipes, nano_pipe, rnode);
	nni_atomic_init(&s->ttl);
	nni_atomic_set(&s->ttl, 8);

	(void) nano_ctx_init(&s->ctx, s);

	// We start off without being either readable or writable.
	// Readability comes when there is something on the socket.
	nni_pollable_init(&s->writable);
	nni_pollable_init(&s->readable);

	debug_msg("&&&&&&&&&&&&nano_sock_init&&&&&&&&&&&&&");
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
nano_pipe_stop(void *arg)
{
	nano_pipe *p = arg;

	nni_aio_stop(&p->aio_send);
	nni_aio_stop(&p->aio_recv);
}

static void
nano_pipe_fini(void *arg)
{
	nano_pipe *p = arg;
	nng_msg *msg;

	if ((msg = nni_aio_get_msg(&p->aio_recv)) != NULL) {
		nni_aio_set_msg(&p->aio_recv, NULL);
		nni_msg_free(msg);
	}

	if ((msg = nni_aio_get_msg(&p->aio_send)) != NULL) {
		nni_aio_set_msg(&p->aio_recv, NULL);
		nni_msg_free(msg);
	}

	nni_aio_fini(&p->aio_send);
	nni_aio_fini(&p->aio_recv);
}

static int
nano_pipe_init(void *arg, nni_pipe *pipe, void *s)
{
	nano_pipe *p = arg;

	nni_aio_init(&p->aio_send, nano_pipe_send_cb, p);
	nni_aio_init(&p->aio_recv, nano_pipe_recv_cb, p);

	NNI_LIST_INIT(&p->sendq, nano_ctx, sqnode);

	p->id   = nni_pipe_id(pipe);
	p->pipe = pipe;
	p->rep  = s;
	return (0);
}

static int
nano_pipe_start(void *arg)
{
	nano_pipe *p = arg;
	nano_sock *s = p->rep;
	int       rv;
	//TODO check MQTT protocol version here
	debug_msg("##########nano_pipe_start################");
	/*
	// TODO check peer protocol
	if (nni_pipe_peer(p->pipe) != NNG_NANO_TCP_PEER) {
		// Peer protocol mismatch.
		return (NNG_EPROTO);
	}
	*/

	//debug_msg("nano_pipe_start peep ver: %s", p->pipe);
	if ((rv = nni_idhash_insert(s->pipes, nni_pipe_id(p->pipe), p)) != 0) {
		return (rv);
	}
	// By definition, we have not received a request yet on this pipe,
	// so it cannot cause us to become writable.
	nni_pipe_recv(p->pipe, &p->aio_recv);
	return (0);
}

static void
nano_pipe_close(void *arg)
{
	nano_pipe *p = arg;
	nano_sock *s = p->rep;
	nano_ctx *ctx;
	void     *tree;

	debug_msg("#################nano_pipe_close!!##############");
	nni_mtx_lock(&s->lk);
	debug_msg("deleting %d", p->id);
	debug_msg("tree : %p", p->tree);

	if (p->tree != NULL) {
		del_all(p->id, p->tree);
	}
	nni_aio_close(&p->aio_send);
	nni_aio_close(&p->aio_recv);

	//nni_mtx_lock(&s->lk);
	p->closed = true;
	if (nni_list_active(&s->recvpipes, p)) {
		// We are no longer "receivable".
		nni_list_remove(&s->recvpipes, p);
	}
	while ((ctx = nni_list_first(&p->sendq)) != NULL) {
		nni_aio *aio;
		nni_msg *msg;
		// Pipe was closed.  To avoid pushing an error back to the
		// entire socket, we pretend we completed this successfully.
		nni_list_remove(&p->sendq, ctx);
		aio = ctx->saio;
		ctx->saio = NULL;
		msg = nni_aio_get_msg(aio);
		nni_aio_set_msg(aio, NULL);
		nni_aio_finish(aio, 0, nni_msg_len(msg));
		nni_msg_free(msg);
	}
	if (p->id == s->ctx.pipe_id) {
		// We "can" send.  (Well, not really, but we will happily
		// accept a message and discard it.)
		nni_pollable_raise(&s->writable);
	}
	nni_idhash_remove(s->pipes, nni_pipe_id(p->pipe));
	nni_mtx_unlock(&s->lk);
}

static void
nano_pipe_send_cb(void *arg)
{
	nano_pipe *p   = arg;
	nano_sock *s   = p->rep;
	nano_ctx *ctx;
	nni_aio  *aio;
	nni_msg  *msg;
	size_t   len;
	uint32_t index = 0;
	uint32_t *pipes;

	debug_msg("##########nano_pipe_send_cb################");
	//retry here
	if (nni_aio_result(&p->aio_send) != 0) {
		nni_msg_free(nni_aio_get_msg(&p->aio_send));
		nni_aio_set_msg(&p->aio_send, NULL);
		nni_pipe_close(p->pipe);
		return;
	}
	nni_mtx_lock(&s->lk);
	p->busy = false;
	if ((ctx = nni_list_first(&p->sendq)) == NULL) {
		// Nothing else to send.
		if (p->id == s->ctx.pipe_id) {
			// Mark us ready for the other side to send!
			nni_pollable_raise(&s->writable);
		}
		nni_mtx_unlock(&s->lk);
		return;
	}

	nni_list_remove(&p->sendq, ctx);
	aio = ctx->saio;
	ctx->saio = NULL;
	p = ctx->spipe;  //should be as same as orignal p?
	ctx->spipe = NULL;
	p->busy    = true;
	msg = ctx->rmsg;
	len = nni_msg_len(msg);
	nni_aio_set_msg(aio, NULL);
	nni_aio_set_msg(&p->aio_send, msg);
	nni_pipe_send(p->pipe, &p->aio_send);

	nni_mtx_unlock(&s->lk);

	nni_aio_finish_synch(aio, 0, len);
	/*
	// pub to mulitple clients/pipes within single aio/ctx
	aio   = ctx->saio;
	pipes = ctx->rspipes;
	p     = ctx->spipe;
	while (index < ctx->pipe_len && ctx->resend_count > 0) {
		if (*(pipes+index) != 0) {
			if (nni_idhash_find(s->pipes, *(pipes+index), (void **) &p) != 0) {
			//Recheck if Pipe is gone.  necessary?
			debug_msg("pipe %d is gone sth went wrong!", *(pipes+index));
			ctx->resend_count --;
			*(pipes+index) = 0;
			} else {
				debug_msg("***************************resending with pipe id : %d %d***************************",
					  *(pipes+index), ctx->resend_count);
				break;
			}
		}
		index ++;
	}
	if (index == ctx->pipe_len) {
		debug_msg("should't reach here!");
		goto drop;
	}

	if (!p->busy) {
		p->busy    = true;
	} else {
		debug_msg("resend failed! message dropped");
		*(pipes+index) = 0;
		ctx->resend_count --;
		goto drop;
	}

	msg        = nni_aio_get_msg(aio);
	len        = nni_msg_len(msg);
	nni_aio_set_msg(&p->aio_send, msg);
	nni_pipe_send(p->pipe, &p->aio_send);
	*(pipes+index) = 0;
	ctx->resend_count --;
drop:
	debug_msg("resending count %d %p", ctx->resend_count, ctx);		//BUG count -1
	if (ctx->resend_count <= 0) {
		nni_list_remove(&p->sendq, ctx);
		ctx->saio  = NULL;
		ctx->spipe = NULL;
		ctx->rspipes = NULL;
		ctx->resend_count = 0;
		ctx->pipe_len = 0;
		nni_aio_set_msg(aio, NULL);
		debug_msg("finish resending");
	}
	nni_mtx_unlock(&s->lk);

	//trigger application level
	if (ctx->resend_count <= 0) {
		nni_aio_finish_synch(aio, 0, len);
	} //else 
	 // nni_aio_finish(aio,0,len);
	debug_msg("end of nano_pipe_send_cb ctx : %p", ctx);
	*/
}

static void
nano_cancel_recv(nni_aio *aio, void *arg, int rv)
{
	nano_ctx *ctx = arg;
	nano_sock *s = ctx->sock;

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
	nano_ctx *ctx = arg;
	nano_sock *s = ctx->sock;
	nano_pipe *p;
	size_t    len;
	nni_msg *msg;

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
			debug_msg("former aio not finish yet");
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

	ctx->pipe_id = nni_pipe_id(p->pipe);
	debug_msg("nano_ctx_recv ends %p pipe: %p pipe_id: %d", ctx, p, ctx->pipe_id);
	nni_mtx_unlock(&s->lk);

	//nni_msg_header_clear(msg);
	nni_aio_set_msg(aio, msg);
	nni_aio_finish(aio, 0, nni_msg_len(msg));
	//nni_mtx_unlock(&s->lk);
}

static void
nano_pipe_recv_cb(void *arg)
{
	nano_pipe *p = arg;
	nano_sock *s = p->rep;
	nano_ctx *ctx;
	nni_msg  *msg;
	uint8_t  *body, *header;
	nni_aio *aio;
	size_t len;
	int    hops;
	int    ttl;

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
	debug_msg("start nano_pipe_recv_cb pipe: %p p_id %d TYPE: %x ===== header: %x %x header len: %d\n", p, p->id,
	          nng_msg_cmd_type(msg), *header, *(header + 1), nng_msg_header_len(msg));
	//ttl = nni_atomic_get(&s->ttl);
	nni_msg_set_pipe(msg, p->id);

	nni_mtx_lock(&s->lk);

	//TODO HOOK
	switch (nng_msg_cmd_type(msg)) {
		case CMD_PUBLISH:
		case CMD_PUBACK:
		case CMD_PUBREC:
		case CMD_PUBREL:
		case CMD_PUBCOMP:
		case CMD_DISCONNECT:
		case CMD_UNSUBSCRIBE:
		case CMD_UNSUBACK:
		case CMD_SUBSCRIBE:
		case CMD_SUBACK:
		case CMD_PINGREQ:
			break;
		default:
			goto drop;
	}

	/*
	if (nng_msg_cmd_type(msg) == CMD_DISCONNECT && (ctx = nni_list_first(&s->recvq)) != NULL)
	{
		aio       = ctx->raio;
		ctx->raio = NULL;
		nni_aio_set_msg(&p->aio_recv, NULL);
		ctx->pipe_id = p->id;
		nni_mtx_unlock(&s->lk);
		nni_aio_set_msg(aio, msg);
		nni_aio_finish_synch(aio, 0, 2);
		debug_msg("client is dead!!");
		return;
	}*/
	if (p->closed) {
		// If we are closed, then we can't return data.
		nni_aio_set_msg(&p->aio_recv, NULL);
		nni_mtx_unlock(&s->lk);
		nni_msg_free(msg);
		debug_msg("ERROR: pipe is closed abruptly!!");
		return;
	}

	if ((ctx = nni_list_first(&s->recvq)) == NULL) {
		// No one waiting to receive yet, holding pattern.
		nni_list_append(&s->recvpipes, p);
		nni_pollable_raise(&s->readable);
		nni_mtx_unlock(&s->lk);
		debug_msg("ERROR: no ctx found!! create more ctxs!");
		return;
	}

	nni_list_remove(&s->recvq, ctx);
	aio = ctx->raio;
	ctx->raio = NULL;
	nni_aio_set_msg(&p->aio_recv, NULL);
	if ((ctx == &s->ctx) && !p->busy) {
		nni_pollable_raise(&s->writable);
	}

	// schedule another receive
	nni_pipe_recv(p->pipe, &p->aio_recv);

	//ctx->pp_len = len;		//TODO Rewrite mqtt header length
	ctx->pipe_id = p->id;            //use pipe id to identify which client
	debug_msg("pipe_id: %d", p->id);

	nni_mtx_unlock(&s->lk);

	nni_aio_set_msg(aio, msg);
	//trigger application level
	nni_aio_finish_synch(aio, 0, nni_msg_len(msg));
	debug_msg("end of nano_pipe_recv_cb %p", ctx);
	return;

	drop:
	nni_msg_free(msg);
	nni_aio_set_msg(&p->aio_recv, NULL);
	nni_pipe_recv(p->pipe, &p->aio_recv);
	debug_msg("drop of nano_pipe_recv_cb %p", ctx);
}

static int
nano_sock_set_max_ttl(void *arg, const void *buf, size_t sz, nni_opt_type t)
{
	nano_sock *s = arg;
	int       ttl;
	int       rv;

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
	int       rv;
	int       fd;

	if ((rv = nni_pollable_getfd(&s->writable, &fd)) != 0) {
		return (rv);
	}
	return (nni_copyout_int(fd, buf, szp, t));
}

static int
nano_sock_get_recvfd(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	nano_sock *s = arg;
	int       rv;
	int       fd;

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
		//{
		//    .o_name = NNG_OPT_REQ_RESENDTIME,
		//    .o_get  = req0_ctx_get_resend_time,
		//    .o_set  = req0_ctx_set_resend_time,
		//},
		// terminate list
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
		.proto_self     = {NNG_NANO_TCP_SELF, NNG_NANO_TCP_SELF_NAME},
		.proto_peer     = {NNG_NANO_TCP_PEER, NNG_NANO_TCP_PEER_NAME},
		.proto_flags    = NNI_PROTO_FLAG_SNDRCV | NNI_PROTO_FLAG_NOMSGQ,
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
