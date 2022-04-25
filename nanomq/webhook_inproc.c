//
// Copyright 2022 NanoMQ Team, Inc. <jaylin@emqx.io>
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

#include "include/webhook_inproc.h"
#include <conf.h>
#include <nano_lmq.h>
#include <nng/nng.h>
#include <nng/protocol/pipeline0/pull.h>
#include <nng/protocol/pipeline0/push.h>
#include <nng/supplemental/http/http.h>
#include <nng/supplemental/util/platform.h>
#include <stdatomic.h>

#define NANO_LMQ_INIT_CAP 16
static atomic_ulong inproc_recv_count = 0;
static atomic_ulong inproc_send_count = 0;
static atomic_ulong inproc_save_count = 0;
static atomic_ulong inproc_aio_count = 0;
typedef struct {
	nng_http_client *client;
	nng_url *        url;
	nng_aio *        aio;
	nng_http_req *   req;
	nng_http_res *   res;
	nng_mtx *        mtx;
	nano_lmq         lmq;
} webhook_client;

// The server keeps a list of work items, sorted by expiration time,
// so that we can use this to set the timeout to the correct value for
// use in poll.
struct hook_work {
	enum { HOOK_INIT, HOOK_RECV, HOOK_WAIT, HOOK_SEND } state;
	nng_aio *      aio;
	nng_msg *      msg;
	webhook_client webhook;
	nng_socket     sock;
	conf_web_hook *conf;
	uint8_t        id;
	bool	       busy;
};

static void webhook_aio_cb(void *arg);
static void handle_msg(void *arg);
static void webhook_cb(void *arg);

static nng_thread *inproc_thr;
static void
fatal(const char *func, int rv)
{
	fprintf(stderr, "%s: %s\n", func, nng_strerror(rv));
	exit(1);
}

static void
webhook_aio_cb(void *arg)
{
	struct hook_work *work        = arg;
	webhook_client *  hook_client = &work->webhook;
	nng_msg  *msg;

	nng_mtx_lock(hook_client->mtx);
	work->busy = false;
	inproc_aio_count++;

	// get msg from lmq and transmit 
	if (nano_lmq_getq(&hook_client->lmq, (void **) &msg) == 0) {
		work->busy = true;
		inproc_save_count--;
		nng_http_req_copy_data(
		    hook_client->req, nng_msg_body(msg), nng_msg_len(msg));
		nng_msg_free(msg);
		inproc_send_count++;
		nng_http_client_transact(hook_client->client, hook_client->req,
		    hook_client->res, hook_client->aio);
	}
	// try to reduce lmq cap
	size_t lmq_len = nano_lmq_len(&hook_client->lmq);
	if (lmq_len > (NANO_LMQ_INIT_CAP * 2)) {
		size_t lmq_cap = nano_lmq_cap(&hook_client->lmq);
		if (lmq_cap > (lmq_len * 2)) {
			nano_lmq_resize(&hook_client->lmq, lmq_cap / 2);
		}
	}
	nng_mtx_unlock(hook_client->mtx);
}

static void
handle_msg(void *arg)
{
	int               rv;
	struct hook_work *work        = arg;
	webhook_client *  hook_client = &work->webhook;

	nng_mtx_lock(hook_client->mtx);
	if (work->busy == false) {
		work->busy = true;
		// get msg and transmit
		nng_http_req_copy_data(hook_client->req,
		    nng_msg_body(work->msg), nng_msg_len(work->msg));
		nng_msg_free(work->msg);
		inproc_send_count++;
		nng_aio_set_timeout(hook_client->aio, 1000);
		nng_http_client_transact(hook_client->client, hook_client->req,
		    hook_client->res, hook_client->aio);
		nng_mtx_unlock(hook_client->mtx);
		return;
	}
	if (nano_lmq_full(&hook_client->lmq)) {
		size_t lmq_cap = nano_lmq_cap(&hook_client->lmq);
		if ((rv = nano_lmq_resize(
		         &hook_client->lmq, lmq_cap + (lmq_cap / 2))) != 0) {
			fatal("nano_lmq_resize", rv);
		}
	}
	inproc_save_count++;
	nano_lmq_putq(&hook_client->lmq, work->msg);
	nng_mtx_unlock(hook_client->mtx);
}

static void
webhook_cb(void *arg)
{
	struct hook_work *work = arg;
	int               rv;

	switch (work->state) {
	case HOOK_INIT:
		work->state = HOOK_RECV;
		nng_recv_aio(work->sock, work->aio);
		break;

	case HOOK_RECV:
		if ((rv = nng_aio_result(work->aio)) != 0) {
			fatal("nng_recv_aio", rv);
		}
		inproc_recv_count++;
		work->msg = nng_aio_get_msg(work->aio);
		handle_msg(work);
		work->msg   = NULL;
		work->state = HOOK_RECV;
		nng_recv_aio(work->sock, work->aio);
		break;

	default:
		fatal("bad state!", NNG_ESTATE);
		break;
	}
}

static int
webhook_init(struct hook_work *w, conf_web_hook *conf)
{
	int             rv;
	webhook_client *webhook = &w->webhook;

	nng_mtx_alloc(&webhook->mtx);
	if (((rv = nng_url_parse(&webhook->url, conf->url)) != 0) ||
	    ((rv = nng_http_client_alloc(&webhook->client, webhook->url)) !=
	        0) ||
	    ((rv = nng_http_req_alloc(&webhook->req, webhook->url)) != 0) ||
	    ((rv = nng_http_res_alloc(&webhook->res)) != 0) ||
	    ((rv = nng_mtx_alloc(&webhook->mtx)) != 0) ||
	    ((rv = nano_lmq_init(&webhook->lmq, NANO_LMQ_INIT_CAP) != 0)) ||
	    ((rv = nng_aio_alloc(&webhook->aio, webhook_aio_cb, w)) != 0)) {
		return rv;
	}

	for (size_t i = 0; i < conf->header_count; i++) {
		nng_http_req_add_header(webhook->req, conf->headers[i]->key,
		    conf->headers[i]->value);
	}
	nng_http_req_set_method(webhook->req, "POST");
	return 0;
}

static struct hook_work *
alloc_work(nng_socket sock, conf_web_hook *conf)
{
	struct hook_work *w;
	int               rv;

	if ((w = nng_alloc(sizeof(*w))) == NULL) {
		fatal("nng_alloc", NNG_ENOMEM);
	}
	if ((rv = nng_aio_alloc(&w->aio, webhook_cb, w)) != 0) {
		fatal("nng_aio_alloc", rv);
	}
	if ((rv = webhook_init(w, conf)) != 0) {
		fatal("webhook_init", rv);
	}
	w->conf  = conf;
	w->sock  = sock;
	w->state = HOOK_INIT;
	w->busy  = false;
	return (w);
}

// The server runs forever.
void
webhook_thr(void *arg)
{
	conf *            conf = arg;
	nng_socket        sock;
	struct hook_work *works[conf->web_hook.pool_size];
	int               rv;
	int               i;

	/*  Create the socket. */
	rv = nng_pull0_open(&sock);
	if (rv != 0) {
		fatal("nng_rep0_open", rv);
	}

	for (i = 0; i < conf->web_hook.pool_size; i++) {
		works[i] = alloc_work(sock, &conf->web_hook);
		works[i]->id = i;
	}

	if ((rv = nng_listen(sock, WEB_HOOK_INPROC_URL, NULL, 0)) != 0) {
		fatal("nng_listen", rv);
	}

	for (i = 0; i < conf->web_hook.pool_size; i++) {
		webhook_cb(works[i]);
	}

	for (;;) {
		// inproc_recv_count;
		// printf("recv count: %lu send count %lu save %lu aio %lu\n", 
		// inproc_recv_count, inproc_send_count, inproc_save_count
		// ,inproc_aio_count);
		// nng_msleep(1000);
		nng_msleep(3600000); // neither pause() nor sleep() portable
	}
}

int
start_webhook_service(conf *conf)
{
	int rv = nng_thread_create(&inproc_thr, webhook_thr, conf);
	if (rv != 0) {
		fatal("nng_thread_create", rv);
	}
	nng_msleep(500);
	return rv;
}

int
stop_webhook_service(void)
{
	nng_thread_destroy(inproc_thr);
	return 0;
}
