//
// Copyright 2026 NanoMQ Team, Inc. <jaylin@emqx.io>
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
#include "nanomq.h"
#include "nng/nng.h"
#include "nng/protocol/pipeline0/pull.h"
#include "nng/protocol/pipeline0/push.h"
#include "nng/supplemental/http/http.h"
#include "nng/supplemental/nanolib/conf.h"
#include "nng/supplemental/nanolib/log.h"
#include "nng/supplemental/nanolib/utils.h"
#include "nng/supplemental/util/platform.h"

#include "nng/mqtt/mqtt_client.h"

#define NANO_LMQ_INIT_CAP 16

// The server keeps a list of work items, sorted by expiration time,
// so that we can use this to set the timeout to the correct value for
// use in poll.
typedef struct hook_work hook_work;
struct hook_work {
	enum { HOOK_INIT, HOOK_RECV, HOOK_WAIT, HOOK_SEND, HOOK_READ_RESPONSE } state;
	nng_aio         *aio;
	nng_aio         *http_aio;
	nng_msg         *msg;
	nng_thread      *thread;
	nng_mtx         *mtx;
	nng_lmq         *lmq;
	nng_socket       sock;
	conf_web_hook   *conf;
	uint32_t         id;
	bool             busy;
	nng_http_req    *req;
	nng_http_client *client;
	nng_http_conn   *conn;
	nng_url         *url;
};

static void hook_work_cb(void *arg);

static nng_thread     *hook_thr;

static void
send_msg(hook_work *w, nng_msg *msg)
{
	conf_web_hook   *conf   = w->conf;
	nng_http_conn   *conn   = NULL;
	nng_aio         *aio    = w->http_aio;
	int              rv;

	nng_mtx_lock(w->mtx);
	if (msg == NULL) {
		rv = nng_lmq_get(w->lmq, &msg);
		log_debug("webhook agent gets msg from lmq to send");
		if (0 != rv) {
			nng_mtx_unlock(w->mtx);
			log_error("Webhook get msg from lmq failed: %s", nng_strerror(rv));
			return;
		}
	}
	if (nng_aio_busy(aio)) {
		if (nng_lmq_full(w->lmq)) {
			size_t lmq_cap = nng_lmq_cap(w->lmq);
			if ((rv = nng_lmq_resize(
			         w->lmq, lmq_cap + (lmq_cap / 2))) != 0) {
				NANO_NNG_FATAL("nng_lmq_resize mem error", rv);
			}
		}
		if (nng_lmq_put(w->lmq, msg) != 0) {
			log_info("HTTP Request droppped");
			nng_msg_free(msg);
		}
	} else {
		if ((rv = nng_http_client_alloc(&w->client, w->url)) != 0) {
			log_error("init failed: %s\n", nng_strerror(rv));
			goto out;
		}
		// Start connection process...
		nng_aio_set_timeout(aio, conf->cancel_timeout);
		nng_aio_set_msg(aio, msg);
		nng_mtx_unlock(w->mtx);
		nng_http_client_connect(w->client, aio);
		return;
	}

out:
	nng_mtx_unlock(w->mtx);
}

// an independent thread of each work obj for sending HTTP msg
static void
http_aio_cb(void *arg)
{
	struct hook_work *work = arg;
	conf_web_hook    *conf = work->conf;
	nng_lmq          *lmq  = work->lmq;
	nng_msg          *msg  = NULL;
	nng_aio          *aio  = work->http_aio;
	int               rv;
	uint8_t type;

	nng_mtx_lock(work->mtx);
	if((rv = nng_aio_result(work->http_aio)) != 0) {
		log_warn("HTTP aio result error : %s", nng_strerror(rv));
		msg = nng_aio_get_msg(work->http_aio);
		if (msg != NULL) {
			type = nng_msg_cmd_type(msg);
			nng_aio_set_msg(work->http_aio, NULL);
			nng_msg_free(msg);
		}
        // FIX: Extract and free the pending HTTP response to prevent memory leaks on error
        nng_http_res *res = nng_aio_get_output(work->http_aio, 1);
        if (res) {
            nng_http_res_free(res);
            nng_aio_set_output(work->http_aio, 1, NULL);
       }
		if (work->conn) {
			nng_http_conn_close(work->conn);
			work->conn = NULL;
		}
		if (work->req) {
			nng_http_req_free(work->req);
			work->req = NULL;
		}
		if (work->client) {
			nng_http_client_free(work->client);
			work->client = NULL;
		}
		nng_mtx_unlock(work->mtx);
		return;
	}
	msg = nng_aio_get_msg(aio);
	nng_aio_set_msg(aio, NULL);

	if (msg != NULL) {
		type = nng_msg_cmd_type(msg);
		
		if (type != CMD_HTTPREQ && type != CMD_HTTPRES) {
			// First callback - connection established
			log_trace("HTTP Connected, sending request");
			if ((rv = nng_http_req_alloc(&work->req, work->url)) != 0) {
				nng_mtx_unlock(work->mtx);
				return;
			}
			work->conn = nng_aio_get_output(aio, 0);

			for (size_t i = 0; i < conf->header_count; i++) {
				nng_http_req_add_header(work->req, conf->headers[i]->key,
					conf->headers[i]->value);
			}

			nng_http_req_set_method(work->req, "POST");
			nng_http_req_set_data(
				work->req, nng_msg_body(msg), nng_msg_len(msg));
			nng_msg_set_cmd_type(msg, CMD_HTTPREQ);
			nng_aio_set_timeout(aio, conf->cancel_timeout);
			nng_aio_set_msg(aio, msg);
			nng_http_conn_write_req(work->conn, work->req, aio);
			nng_mtx_unlock(work->mtx);
			return;
			
		} else if (type == CMD_HTTPREQ) {
			// Second callback - request sent, now read response
			log_trace("HTTP Request sent, reading response");
			
			nng_http_res *res;
			if ((rv = nng_http_res_alloc(&res)) != 0) {
				log_error("Failed to allocate response: %s", nng_strerror(rv));
				nng_msg_free(msg);
				nng_aio_set_msg(work->http_aio, NULL);
				nng_mtx_unlock(work->mtx);
				nng_http_conn_close(work->conn);
				work->conn = NULL;
				nng_http_req_free(work->req);
				work->req = NULL;
				nng_http_client_free(work->client);
				work->client = NULL;
				return;
			}
			
			// Mark message to indicate we're reading response
			nng_msg_set_cmd_type(msg, CMD_HTTPRES);
			nng_aio_set_msg(aio, msg);
			nng_aio_set_timeout(aio, conf->cancel_timeout);
			
			// Store response object for cleanup later
			nng_aio_set_output(aio, 1, res);
			
			// Read the response
			nng_http_conn_read_res(work->conn, res, aio);
			nng_mtx_unlock(work->mtx);
			return;
			
		} else if (type == CMD_HTTPRES) {
			// Third callback - response received, now cleanup
			nng_http_res *res = nng_aio_get_output(aio, 1);

			if (res) {
				int status = nng_http_res_get_status(res);
				log_trace("HTTP Response received: %d", status);
				nng_http_res_free(res);
			}
			
			nng_msg_free(msg);
			nng_aio_set_msg(work->http_aio, NULL);
			nng_mtx_unlock(work->mtx);
			nng_http_conn_close(work->conn);
			work->conn = NULL;
			nng_http_req_free(work->req);
			work->req = NULL;
			nng_http_client_free(work->client);
			work->client = NULL;
			log_trace("HTTP Request succeed");
		}
	} else {
		log_info("NULL msg from webhook aio !!!!");
		nng_mtx_unlock(work->mtx);
	}

	if (!nng_lmq_empty(lmq)) {
		// send next webhook http request
		if ((rv = nng_http_client_alloc(&work->client, work->url)) != 0) {
			log_error("init failed: %s\n", nng_strerror(rv));
			return;
		}
		nng_mtx_lock(work->mtx);
		nng_lmq_get(lmq, &msg);
		nng_aio_set_timeout(work->http_aio, conf->cancel_timeout);
		nng_aio_set_msg(work->http_aio, msg);
		nng_http_client_connect(work->client, work->http_aio);
		nng_mtx_unlock(work->mtx);
	} else {
		size_t lmq_len = nng_lmq_len(work->lmq);
		// try to reduce lmq cap
		if (lmq_len > (NANO_LMQ_INIT_CAP * 2)) {
			nng_mtx_lock(work->mtx);
			size_t lmq_cap = nng_lmq_cap(work->lmq);
			if (lmq_cap > (lmq_len * 2)) {
				nng_lmq_resize(work->lmq, lmq_cap / 2);
			}
			nng_mtx_unlock(work->mtx);
		}
	}
}

static void
hook_work_cb(void *arg)
{
	struct hook_work *work = arg;
	int               rv;
	char *            body;
	size_t            body_len;
	nng_msg *         msg;
	cJSON *           root;

	switch (work->state) {
	case HOOK_INIT:
		work->state = HOOK_RECV;
		// get MQTT msg from broker via inproc aio
		nng_recv_aio(work->sock, work->aio);
		break;

	case HOOK_RECV:
		if ((rv = nng_aio_result(work->aio)) != 0) {
			NANO_NNG_FATAL("nng_recv_aio", rv);
		}

		work->msg = nng_aio_get_msg(work->aio);

		msg      = work->msg;
		body     = (char *) nng_msg_body(msg);
		body_len = nng_msg_len(msg);
		send_msg(work, msg);
		work->msg   = NULL;
		work->state = HOOK_RECV;
		nng_recv_aio(work->sock, work->aio);
		break;
	default:
		NANO_NNG_FATAL("bad state!", NNG_ESTATE);
		break;
	}
}

static struct hook_work *
alloc_work(nng_socket sock, conf_web_hook *conf)
{
	struct hook_work *w;
	int               rv;

	if ((w = nng_alloc(sizeof(*w))) == NULL) {
		NANO_NNG_FATAL("nng_alloc", NNG_ENOMEM);
	}
	if ((rv = nng_aio_alloc(&w->aio, hook_work_cb, w)) != 0) {
		NANO_NNG_FATAL("nng_aio_alloc", rv);
	}
	if ((rv = nng_mtx_alloc(&w->mtx)) != 0) {
		NANO_NNG_FATAL("nng_mtx_alloc", rv);
	}
	if ((rv = nng_lmq_alloc(&w->lmq, NANO_LMQ_INIT_CAP)) != 0) {
		NANO_NNG_FATAL("nng_lmq_alloc", rv);
	}
	if (conf->enable) {
		if ((rv = nng_aio_alloc(&w->http_aio, http_aio_cb, w)) != 0) {
			NANO_NNG_FATAL("nng_aio_alloc", rv);
		}
		if ((rv = nng_url_parse(&w->url, conf->url)) != 0) {
			NANO_NNG_FATAL("nng_http_alloc", rv);
		}
	}

	w->conf     = conf;
	w->sock     = sock;
	w->state    = HOOK_INIT;
	w->busy     = false;
	w->conn     = NULL;
	w->req      = NULL;
	w->client   = NULL;

	return (w);
}

// The server runs forever.
static void
hook_cb(void *arg)
{
	conf              *conf = arg;
	nng_socket         sock;
	size_t             works_num = 0;
	int                rv;
	size_t             i;

	if (conf->web_hook.enable) {
		works_num += conf->web_hook.pool_size;
	}
	struct hook_work **works =
	    nng_zalloc(works_num * sizeof(struct hook_work *));

	/* Create the socket. */
	rv = nng_pull0_open(&sock);
	if (rv != 0) {
		log_error("nng_pull0_open %d", rv);
		nng_free(works, works_num * sizeof(struct hook_work *));
		return;
	}

	for (i = 0; i < works_num; i++) {
		works[i] = alloc_work(sock, &conf->web_hook);
		works[i]->id = i;
	}

	char *hook_ipc_url =
	    conf->hook_ipc_url == NULL ? HOOK_IPC_URL : conf->hook_ipc_url;
	// NanoMQ core thread talks to others via INPROC
	if ((rv = nng_listen(sock, hook_ipc_url, NULL, 0)) != 0) {
		log_error("hook nng_listen %d", rv);
		goto out;
	}

	for (i = 0; i < works_num; i++) {
		// shares taskq threads with broker
		hook_work_cb(works[i]);
	}

	for (;;) {
		nng_msleep(3600000); // neither pause() nor sleep() portable
	}

out:
	for (i = 0; i < works_num; i++) {
		nng_free(works[i], sizeof(struct hook_work));
	}
	nng_free(works, works_num * sizeof(struct hook_work *));
}

int
start_hook_service(conf *conf)
{
	int rv = nng_thread_create(&hook_thr, hook_cb, conf);
	if (rv != 0) {
		NANO_NNG_FATAL("nng_thread_create", rv);
	}
	nng_msleep(500);
	return rv;
}

int
stop_hook_service(void)
{
	nng_thread_destroy(hook_thr);
	return 0;
}

