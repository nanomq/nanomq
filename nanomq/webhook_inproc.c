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

#include "include/webhook_inproc.h"
#include <conf.h>
#include <nng/nng.h>
#include <nng/protocol/pipeline0/pull.h>
#include <nng/protocol/pipeline0/push.h>
#include <nng/supplemental/http/http.h>
#include <nng/supplemental/util/platform.h>

typedef struct {
	nng_http_client *client;
	nng_url *        url;
	nng_aio *        aio;
	nng_http_req *   req;
	nng_http_res *   res;
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
};

static nng_thread *inproc_thr;

static void
fatal(const char *func, int rv)
{
	fprintf(stderr, "%s: %s\n", func, nng_strerror(rv));
	exit(1);
}

static void
webhook_cb(void *arg)
{
	struct hook_work *work = arg;
	nng_msg *         msg;
	int               rv;
	uint32_t          when;

	switch (work->state) {
	case HOOK_INIT:
		work->state = HOOK_RECV;
		nng_recv_aio(work->sock, work->aio);
		break;

	case HOOK_RECV:
		if ((rv = nng_aio_result(work->aio)) != 0) {
			fatal("nng_recv_aio", rv);
		}
		msg         = nng_aio_get_msg(work->aio);
		work->msg   = msg;
		work->state = HOOK_WAIT;
		nng_sleep_aio(0, work->aio);
		break;

	case HOOK_WAIT:
		for (size_t i = 0; i < work->conf->header_count; i++) {
			nng_http_req_add_header(work->webhook.req,
			    work->conf->headers[i]->key,
			    work->conf->headers[i]->value);
		}
		nng_http_req_set_method(work->webhook.req, "POST");
		nng_http_req_copy_data(work->webhook.req,
		    nng_msg_body(work->msg), nng_msg_len(work->msg));

		// printf("get post: %s\n", (char *)nng_msg_body(work->msg));
		nng_msg_free(work->msg);
		work->msg = NULL;

		nng_aio_wait(work->webhook.aio);
		if ((rv = nng_aio_result(work->webhook.aio)) != 0) {
			work->state = HOOK_RECV;
			nng_recv_aio(work->sock, work->aio);
			break;
		}
		nng_http_client_transact(work->webhook.client,
		    work->webhook.req, work->webhook.res, work->webhook.aio);

		work->state = HOOK_RECV;
		nng_recv_aio(work->sock, work->aio);
		break;

	default:
		fatal("bad state!", NNG_ESTATE);
		break;
	}
}

static int
webhook_init(webhook_client *webhook, conf_web_hook *conf)
{
	int rv;
	if (((rv = nng_url_parse(&webhook->url, conf->url)) != 0) ||
	    ((rv = nng_http_client_alloc(&webhook->client, webhook->url)) !=
	        0) ||
	    ((rv = nng_http_req_alloc(&webhook->req, webhook->url)) != 0) ||
	    ((rv = nng_http_res_alloc(&webhook->res)) != 0) ||
	    ((rv = nng_aio_alloc(&webhook->aio, NULL, NULL)) != 0)) {
		return rv;
	}
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
	if ((rv = webhook_init(&w->webhook, conf)) != 0) {
		fatal("webhook_init", rv);
	}
	w->conf  = conf;
	w->sock  = sock;
	w->state = HOOK_INIT;
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
	}

	if ((rv = nng_listen(sock, WEB_HOOK_INPROC_URL, NULL, 0)) != 0) {
		fatal("nng_listen", rv);
	}

	for (i = 0; i < conf->web_hook.pool_size; i++) {
		webhook_cb(
		    works[i]); // this starts them going (HOOK_INIT state)
	}

	for (;;) {
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
