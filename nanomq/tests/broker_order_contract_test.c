//
// Copyright 2026 NanoMQ Team, Inc. <jaylin@emqx.io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

// Check inline and backlog ordering, bounded callback depth and cancellation.
// No real transport or scheduling sleeps are needed to exercise either path.
#include "core/nng_impl.h"
#include "core/sockimpl.h"
#include "include/broker.h"
#include "nng/protocol/mqtt/mqtt_parser.h"
#include "nng/protocol/mqtt/nmq_mqtt.h"
#include "nng/supplemental/nanolib/hash_table.h"
#include "nng/supplemental/nanolib/utils.h"
#include "supplemental/mqtt/mqtt_qos_db_api.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(expr)                                                          \
	do {                                                                  \
		if (!(expr)) {                                                 \
			fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expr); \
			abort();                                               \
		}                                                             \
	} while (0)

typedef struct {
	nni_pipe   *pipe;
	conn_param *cp;
	nni_aio *recv;
	unsigned receives;
	bool finalized;
} order_test_pipe;

static int
test_pipe_init(void *arg, nni_pipe *pipe)
{
	order_test_pipe *p = arg;
	p->pipe = pipe;
	nni_pipe_set_conn_param(pipe, p->cp);
	// Match the decoded connection ownership of a real transport.
	conn_param_clone(p->cp);
	return 0;
}

static void
test_pipe_fini(void *arg)
{
	order_test_pipe *p = arg;
	if (p->pipe->nano_qos_db != NULL) {
		nni_qos_db_fini_id_hash(p->pipe->nano_qos_db);
	}
	conn_param_free(p->cp);
	p->finalized = true;
}

static void
test_pipe_close(void *arg)
{
	order_test_pipe *p = arg;
	if (p->recv != NULL) {
		nni_aio *aio = p->recv;
		p->recv = NULL;
		nni_aio_finish_error(aio, NNG_ECLOSED);
	}
}

static void
test_pipe_recv(void *arg, nni_aio *aio)
{
	order_test_pipe *p = arg;
	CHECK(p->recv == NULL);
	CHECK(nni_aio_begin(aio) == 0);
	p->recv = aio;
	p->receives++;
}

static int
test_pipe_getopt(void *arg, const char *name, void *buf, size_t *sz,
    nni_opt_type type)
{
	NNI_ARG_UNUSED(arg);
	NNI_ARG_UNUSED(name);
	NNI_ARG_UNUSED(buf);
	NNI_ARG_UNUSED(sz);
	NNI_ARG_UNUSED(type);
	return NNG_ENOTSUP;
}

static nni_sp_pipe_ops test_pipe_ops = {
	.p_init   = test_pipe_init,
	.p_fini   = test_pipe_fini,
	.p_close  = test_pipe_close,
	.p_recv   = test_pipe_recv,
	.p_getopt = test_pipe_getopt,
};

static nni_sp_tran test_transport = { .tran_pipe = &test_pipe_ops };

static void
expect_event(nng_socket sock, uint8_t command)
{
	nng_msg *msg;
	CHECK(nng_recvmsg(sock, &msg, 0) == 0);
	CHECK(nng_msg_cmd_type(msg) == command);
	conn_param *cp = nng_msg_get_conn_param(msg);
	conn_param_free(cp);
	if (command == CMD_DISCONNECT_EV) {
		// Disconnect transfers the retired protocol reference as well.
		conn_param_free(cp);
	}
	nng_msg_free(msg);
}

static void
create_pipe(nni_sock *core, nng_socket sock, order_test_pipe *p,
    const char *client_id)
{
	nni_listener listener = { .l_sock = core, .l_tran = &test_transport };
	memset(p, 0, sizeof(*p));
	CHECK(conn_param_alloc(&p->cp) == 0);
	conn_param_set_clientid(p->cp, client_id);
	conn_param_set_username(p->cp, "order-user");
	p->cp->pro_name.body = nng_strdup("MQTT");
	CHECK(p->cp->pro_name.body != NULL);
	p->cp->pro_name.len = 4;
	p->cp->pro_ver = 5;
	p->cp->con_flag = 0x82;
	p->cp->clean_start = 1;
	p->cp->keepalive_mqtt = 60;
	CHECK(nni_pipe_create_listener(&p->pipe, &listener, p) == 0);
	// Keep the creation reference; the stack listener is no longer needed.
	p->pipe->p_listener = NULL;
	CHECK(p->pipe->p_proto_ops.pipe_start(p->pipe->p_proto_data) == 0);
	expect_event(sock, CMD_CONNACK);
}

static void
dispose_pipe(nng_socket sock, order_test_pipe *p)
{
	nni_pipe_close(p->pipe);
	expect_event(sock, CMD_DISCONNECT_EV);
	nni_pipe_rele(p->pipe);
	nni_reap_drain();
}


static void
inject_publish(order_test_pipe *p, uint8_t sequence)
{
	CHECK(p->recv != NULL);
	nni_aio *aio = p->recv;
	p->recv = NULL;
	nng_msg *msg;
	CHECK(nng_msg_alloc(&msg, 0) == 0);
	// Supply the wire header as well as the protocol command metadata.
	uint8_t header[] = { CMD_PUBLISH, 1 };
	CHECK(nng_msg_header_append(msg, header, sizeof(header)) == 0);
	CHECK(nng_msg_append(msg, &sequence, 1) == 0);
	nng_msg_set_cmd_type(msg, CMD_PUBLISH);
	nng_msg_set_conn_param(msg, p->cp);
	nni_aio_set_msg(aio, msg);
	nni_aio_finish_sync(aio, 0, 1);
}

static void
consume(nng_aio *aio, uint8_t sequence)
{
	nng_aio_wait(aio);
	CHECK(nng_aio_result(aio) == 0);
	nng_msg *msg = nng_aio_get_msg(aio);
	CHECK(msg != NULL && nng_msg_len(msg) == 1);
	CHECK(*(uint8_t *) nng_msg_body(msg) == sequence);
	conn_param_free(nng_msg_get_conn_param(msg));
	nng_msg_free(msg);
	nng_aio_set_msg(aio, NULL);
}

// Model the broker's inline RECV -> WAIT fanout. The next packet must
// remain unread throughout this callback, even with another worker ready.
static void
check_inline_delivery(void *arg)
{
	order_test_pipe *p = arg;
	CHECK(p->recv == NULL);
}

typedef struct {
	nni_mtx lock;
	nni_cv  cv;
	bool    entered;
	bool    release;
} delayed_delivery;

static void
hold_backlog_delivery(void *arg)
{
	delayed_delivery *d = arg;
	nni_mtx_lock(&d->lock);
	d->entered = true;
	nni_cv_wake(&d->cv);
	while (!d->release) {
		nni_cv_wait(&d->cv);
	}
	nni_mtx_unlock(&d->lock);
}

typedef struct {
	nng_ctx ctx;
	nng_aio *aio;
} receive_call;

static void
receive_thread(void *arg)
{
	receive_call *call = arg;
	nng_ctx_recv(call->ctx, call->aio);
}

typedef struct {
	nng_ctx ctx;
	nng_aio *aio;
	order_test_pipe *pipes[2];
	unsigned count, depth, limit;
	int end_error;
} receive_chain;

static void
chain_callback(void *arg)
{
	receive_chain *chain = arg;
	if (nng_aio_result(chain->aio) != 0) {
		CHECK(chain->end_error != 0);
		CHECK(nng_aio_result(chain->aio) == chain->end_error);
		return;
	}
	CHECK(++chain->depth == 1);
	nng_msg *msg = nng_aio_get_msg(chain->aio);
	CHECK(msg != NULL);
	CHECK(*(uint8_t *) nng_msg_body(msg) == (uint8_t) chain->count);
	CHECK(chain->pipes[chain->count % 2]->recv == NULL);
	conn_param_free(nng_msg_get_conn_param(msg));
	nng_msg_free(msg);
	nng_aio_set_msg(chain->aio, NULL);
	chain->count++;
	if (chain->count < chain->limit) {
		inject_publish(chain->pipes[chain->count % 2],
		    (uint8_t) chain->count);
		nng_ctx_recv(chain->ctx, chain->aio);
	} else if (chain->end_error) {
		// End the reentrant request while it is off the public recvq.
		if (chain->end_error == NNG_ETIMEDOUT) {
			nng_aio_set_timeout(chain->aio, 1);
		}
		nng_ctx_recv(chain->ctx, chain->aio);
		if (chain->end_error == NNG_ECANCELED) {
			nng_aio_cancel(chain->aio);
		} else if (chain->end_error == NNG_ECLOSED) {
			CHECK(nng_ctx_close(chain->ctx) == 0);
		} else {
			nng_msleep(20);
		}
	}
	chain->depth--;
}

typedef struct {
	nng_aio *aio;
	order_test_pipe *source;
	order_test_pipe *replacement;
	nni_sock *core;
	nng_socket sock;
} closing_delivery;

static void
close_during_delivery(void *arg)
{
	closing_delivery *delivery = arg;
	nng_msg *msg = nng_aio_get_msg(delivery->aio);
	CHECK(msg != NULL && delivery->source->recv == NULL);
	uint32_t id = nni_pipe_id(delivery->source->pipe);
	nni_pipe_close(delivery->source->pipe);
	// No delivery reference should delay reaping. In particular, returning
	// from this callback must not dereference the now-freed source.
	nni_pipe_rele(delivery->source->pipe);
	nni_reap_drain();
	CHECK(delivery->source->finalized);
	expect_event(delivery->sock, CMD_DISCONNECT_EV);
	// The delivered message's independent cparam reference remains valid
	// even after both the source and its disconnect event are gone.
	conn_param *cp = nng_msg_get_conn_param(msg);
	CHECK(strcmp((char *) conn_param_get_clientid(cp), "order-first") == 0);
	CHECK(*(uint8_t *) nng_msg_body(msg) == 7);
	conn_param_free(cp);
	nng_msg_free(msg);
	nng_aio_set_msg(delivery->aio, NULL);
	create_pipe(delivery->core, delivery->sock, delivery->replacement,
	    "order-first");
	CHECK(nni_pipe_id(delivery->replacement->pipe) == id);
}

static void
cache_during_delivery(void *arg)
{
	closing_delivery *delivery = arg;
	nng_msg *msg = nng_aio_get_msg(delivery->aio);
	CHECK(msg != NULL && delivery->source->recv == NULL);
	conn_param_free(nng_msg_get_conn_param(msg));
	nng_msg_free(msg);
	nng_aio_set_msg(delivery->aio, NULL);
	// Session caching removes a resume registration without destroying
	// the source. It must not start another receive on the cached pipe.
	delivery->source->cp->clean_start = 0;
	nni_pipe_close(delivery->source->pipe);
	CHECK(nni_atomic_get_bool(&delivery->source->pipe->cache));
}

typedef struct {
	nng_ctx ctx;
	nng_aio *aio;
	order_test_pipe *retiring, *next;
	unsigned phase;
} event_delivery;

static void
event_between_publications(void *arg)
{
	event_delivery *d = arg;
	CHECK(nng_aio_result(d->aio) == 0);
	nng_msg *msg = nng_aio_get_msg(d->aio);
	CHECK(msg != NULL);
	unsigned phase = d->phase++;
	if (phase == 1) {
		CHECK(nng_msg_cmd_type(msg) == CMD_DISCONNECT_EV);
		// The notification owns both the retired and the notification ref.
		conn_param_free(nng_msg_get_conn_param(msg));
	} else {
		CHECK(phase == 0 || phase == 2);
		CHECK(nng_msg_get_type(msg) == CMD_PUBLISH);
		CHECK(*(uint8_t *) nng_msg_body(msg) == (phase == 0 ? 80 : 81));
	}
	conn_param_free(nng_msg_get_conn_param(msg));
	nng_msg_free(msg);
	nng_aio_set_msg(d->aio, NULL);
	if (phase == 0) {
		// No worker is on recvq. Closing this third pipe queues waitlmq.
		nni_pipe_close(d->retiring->pipe);
		nni_pipe_rele(d->retiring->pipe);
		inject_publish(d->next, 81);
	}
	if (phase < 2) {
		nng_ctx_recv(d->ctx, d->aio);
	}
}

int
main(void)
{
	conf *cfg = nng_zalloc(sizeof(*cfg));
	CHECK(cfg != NULL);
	conf_init(cfg);
	nng_socket sock = { .data = cfg };
	CHECK(nng_nmq_tcp0_open(&sock) == 0);
	CHECK(nng_socket_set_ms(sock, NNG_OPT_RECVTIMEO, 1000) == 0);
	nni_sock *core;
	CHECK(nni_sock_find(&core, sock.id) == 0);
	dbhash_init_pipe_table();
	nanomq_init_hash_seed();
	order_test_pipe first, second;
	create_pipe(core, sock, &first, "order-first");
	create_pipe(core, sock, &second, "order-second");
	nng_ctx a, b;
	nng_aio *aa, *ba, *inline_aio;
	delayed_delivery delayed = { 0 };
	nni_mtx_init(&delayed.lock);
	nni_cv_init(&delayed.cv, &delayed.lock);
	CHECK(nng_ctx_open(&a, sock) == 0);
	CHECK(nng_ctx_open(&b, sock) == 0);
	CHECK(nng_aio_alloc(&aa, hold_backlog_delivery, &delayed) == 0);
	CHECK(nng_aio_alloc(&ba, NULL, NULL) == 0);
	CHECK(nng_aio_alloc(&inline_aio, check_inline_delivery, &first) == 0);
	nng_aio_set_timeout(aa, 1000);
	nng_aio_set_timeout(ba, 1000);

	// The normal path runs application fanout before rearming the source.
	// The assertion inside check_inline_delivery fails on the old code.
	nng_ctx_recv(a, inline_aio);
	nng_ctx_recv(b, ba);
	unsigned receives = first.receives;
	inject_publish(&first, 1);
	consume(inline_aio, 1);
	CHECK(first.recv != NULL && first.receives == receives + 1);
	CHECK(nng_aio_busy(ba));
	inject_publish(&second, 2);
	consume(ba, 2);
	CHECK(second.recv != NULL);
	nng_aio_free(inline_aio);

	// Deliberately delay application processing of a backlogged PUBLISH.
	// A synchronous backlog delivery must keep its source paused too.
	receives = first.receives;
	inject_publish(&first, 3);
	receive_call call = { a, aa };
	nng_thread *delivery;
	CHECK(nng_thread_create(&delivery, receive_thread, &call) == 0);
	nni_mtx_lock(&delayed.lock);
	nni_time deadline = nni_clock() + 1000;
	while (!delayed.entered) {
		CHECK(nni_cv_until(&delayed.cv, deadline) == 0);
	}
	nni_mtx_unlock(&delayed.lock);
	CHECK(first.recv == NULL && first.receives == receives);
	// An independent connection can still make progress during fanout.
	nng_ctx_recv(b, ba);
	inject_publish(&second, 4);
	consume(ba, 4);
	CHECK(nng_aio_busy(aa));
	nni_mtx_lock(&delayed.lock);
	delayed.release = true;
	nni_cv_wake(&delayed.cv);
	nni_mtx_unlock(&delayed.lock);
	nng_thread_destroy(delivery);
	consume(aa, 3);
	CHECK(first.recv != NULL && first.receives == receives + 1);

	// A long succession of backlogged pipes must not grow the callback stack.
	receive_chain chain = { .ctx = a, .pipes = { &first, &second },
	    .limit = 10000 };
	CHECK(nng_aio_alloc(&chain.aio, chain_callback, &chain) == 0);
	int input_sentinel;
	nng_aio_set_input(chain.aio, 0, &input_sentinel);
	inject_publish(&first, 0);
	nng_ctx_recv(a, chain.aio);
	nng_aio_wait(chain.aio);
	CHECK(chain.count == chain.limit && chain.depth == 0);
	CHECK(nng_aio_get_input(chain.aio, 0) == &input_sentinel);
	CHECK(first.recv != NULL && second.recv != NULL);
	int end_errors[] = { NNG_ECANCELED, NNG_ETIMEDOUT, NNG_ECLOSED };
	for (unsigned i = 0; i < sizeof(end_errors) / sizeof(end_errors[0]); i++) {
		chain.count = 0;
		chain.limit = 1;
		chain.end_error = end_errors[i];
		nng_aio_set_timeout(chain.aio, NNG_DURATION_INFINITE);
		if (chain.end_error == NNG_ECLOSED) {
			CHECK(nng_ctx_open(&chain.ctx, sock) == 0);
		}
		inject_publish(&first, 0);
		nng_ctx_recv(chain.ctx, chain.aio);
		nng_aio_wait(chain.aio);
		CHECK(nng_aio_result(chain.aio) == chain.end_error);
		CHECK(chain.count == 1 && chain.depth == 0);
		CHECK(first.recv != NULL);
	}
	nng_aio_free(chain.aio);

	// waitlmq wins over recvpipes on the next iteration, without retaining
	// the previous resume registration or losing the next receive request.
	order_test_pipe retiring;
	create_pipe(core, sock, &retiring, "order-retiring");
	event_delivery events = { .ctx = a, .retiring = &retiring,
	    .next = &second };
	CHECK(nng_aio_alloc(&events.aio, event_between_publications, &events) == 0);
	unsigned first_refs = first.pipe->p_ref, second_refs = second.pipe->p_ref;
	inject_publish(&first, 80);
	nng_ctx_recv(a, events.aio);
	nng_aio_wait(events.aio);
	CHECK(events.phase == 3);
	CHECK(first.pipe->p_ref == first_refs && second.pipe->p_ref == second_refs);
	CHECK(first.recv != NULL && second.recv != NULL);
	nng_aio_free(events.aio);
	nni_reap_drain();

	// Reject a second receive without cancelling the original waiter.
	nng_aio *waiting, *duplicate;
	CHECK(nng_aio_alloc(&waiting, NULL, NULL) == 0);
	CHECK(nng_aio_alloc(&duplicate, NULL, NULL) == 0);
	nng_ctx_recv(a, waiting);
	nng_ctx_recv(a, duplicate);
	nng_aio_wait(duplicate);
	CHECK(nng_aio_result(duplicate) == NNG_ESTATE);
	CHECK(nng_aio_busy(waiting));
	nng_aio_cancel(waiting);
	nng_aio_wait(waiting);
	CHECK(nng_aio_result(waiting) == NNG_ECANCELED);
	nng_aio_free(duplicate);
	nng_aio_free(waiting);

	// Cancelling a waiting worker must leave the source available to B.
	nng_ctx_recv(a, aa);
	CHECK(first.recv != NULL);
	nng_aio_cancel(aa);
	nng_aio_wait(aa);
	CHECK(nng_aio_result(aa) == NNG_ECANCELED);
	inject_publish(&first, 5);
	nng_ctx_recv(b, ba);
	CHECK(second.recv != NULL);
	consume(ba, 5);
	CHECK(first.recv != NULL);

	// Reconnect with the same hashed pipe ID while the workers stay alive.
	dispose_pipe(sock, &first);
	// The replacement has the same hashed pipe ID and its own pending I/O.
	create_pipe(core, sock, &first, "order-first");
	receives = first.receives;
	nng_ctx_recv(b, ba);
	CHECK(first.recv != NULL && first.receives == receives);
	inject_publish(&second, 6);
	consume(ba, 6);
	CHECK(second.recv != NULL);
	order_test_pipe replacement;
	closing_delivery closing = { .source = &first, .replacement = &replacement,
	    .core = core, .sock = sock };
	CHECK(nng_aio_alloc(&closing.aio, close_during_delivery, &closing) == 0);
	receives = first.receives;
	inject_publish(&first, 7);
	nng_ctx_recv(a, closing.aio);
	nng_aio_wait(closing.aio);
	CHECK(first.receives == receives && first.recv == NULL);
	CHECK(first.finalized);
	CHECK(replacement.recv != NULL && replacement.receives == 1);
	nng_aio_free(closing.aio);
	// The replacement remains usable after the old delivery returns.
	nng_ctx_recv(b, ba);
	inject_publish(&replacement, 8);
	consume(ba, 8);
	dispose_pipe(sock, &replacement);

	order_test_pipe cached;
	create_pipe(core, sock, &cached, "order-cached");
	closing_delivery caching = { .source = &cached };
	CHECK(nng_aio_alloc(&caching.aio, cache_during_delivery, &caching) == 0);
	receives = cached.receives;
	inject_publish(&cached, 9);
	nng_ctx_recv(a, caching.aio);
	nng_aio_wait(caching.aio);
	CHECK(cached.receives == receives && cached.recv == NULL);
	CHECK(!cached.finalized);
	nng_aio_free(caching.aio);
	// Expire the synthetic cached session, without a disconnect event.
	nni_atomic_set_bool(&cached.pipe->cache, false);
	nni_pipe_close(cached.pipe);
	nni_pipe_rele(cached.pipe);
	nni_reap_drain();
	CHECK(cached.finalized);
	CHECK(nng_ctx_close(b) == 0);
	CHECK(nng_ctx_close(a) == 0);
	dispose_pipe(sock, &second);
	nng_aio_free(aa);
	nng_aio_free(ba);
	nni_cv_fini(&delayed.cv);
	nni_mtx_fini(&delayed.lock);
	nni_sock_rele(core);
	CHECK(nng_close(sock) == 0);
	nni_reap_drain();
	dbhash_destroy_pipe_table();
	nng_fini();
	puts("PASS inline/backlog ordering, bounded reentry, cancel and close");
	return 0;
}
