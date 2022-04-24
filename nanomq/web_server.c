
//
// Copyright 2020 NanoMQ Team, Inc. <jaylin@emqx.io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#define INPROC_URL "inproc://rest"
#define REST_URL "http://0.0.0.0:%u/api/v1"

#include "nng/nng.h"
#include "nng/protocol/reqrep0/rep.h"
#include "nng/protocol/reqrep0/req.h"
#include "nng/supplemental/http/http.h"
#include "nng/supplemental/util/platform.h"

#include "include/nanomq.h"
#include "include/rest_api.h"
#include "include/web_server.h"
// #include "utils/log.h"

#define fatal(msg, rv)                                    \
	{                                                 \
		printf("%s:%s\n", msg, nng_strerror(rv)); \
		exit(1);                                  \
	}

typedef enum {
	SEND_REQ, // Sending REQ request
	RECV_REP, // Receiving REQ reply
} job_state;

typedef struct rest_job {
	nng_aio *        http_aio; // aio from HTTP we must reply to
	nng_http_res *   http_res; // HTTP response object
	job_state        state;    // 0 = sending, 1 = receiving
	nng_msg *        msg;      // request message
	nng_aio *        aio;      // request flow
	nng_ctx          ctx;      // context on the request socket
	struct rest_job *next;     // next on the freelist
} rest_job;

static nng_socket        req_sock;
static nng_mtx *         job_lock;
static rest_job *        job_freelist;
static nng_mtx *         mtx_log;
static nng_thread *      inproc_thr;
static FILE *            logfile;
static conf_http_server *http_server_conf;
static conf *            global_config;

static void rest_job_cb(void *arg);

static void
rest_recycle_job(rest_job *job)
{
	if (job->http_res != NULL) {
		nng_http_res_free(job->http_res);
		job->http_res = NULL;
	}
	if (job->msg != NULL) {
		nng_msg_free(job->msg);
		job->msg = NULL;
	}
	if (nng_ctx_id(job->ctx) != 0) {
		nng_ctx_close(job->ctx);
	}

	nng_mtx_lock(job_lock);
	job->next    = job_freelist;
	job_freelist = job;
	nng_mtx_unlock(job_lock);
}

static rest_job *
rest_get_job(void)
{
	rest_job *job;

	nng_mtx_lock(job_lock);
	if ((job = job_freelist) != NULL) {
		job_freelist = job->next;
		nng_mtx_unlock(job_lock);
		job->next = NULL;
		return (job);
	}
	nng_mtx_unlock(job_lock);
	if ((job = calloc(1, sizeof(*job))) == NULL) {
		return (NULL);
	}
	if (nng_aio_alloc(&job->aio, rest_job_cb, job) != 0) {
		free(job);
		return (NULL);
	}
	return (job);
}

static void
rest_http_fatal(rest_job *job, const char *fmt, int rv)
{
	char          buf[128];
	nng_aio *     aio = job->http_aio;
	nng_http_res *res = job->http_res;

	job->http_res = NULL;
	job->http_aio = NULL;
	snprintf(buf, sizeof(buf), fmt, nng_strerror(rv));
	nng_http_res_set_status(res, NNG_HTTP_STATUS_INTERNAL_SERVER_ERROR);
	nng_http_res_set_reason(res, buf);
	nng_aio_set_output(aio, 0, res);
	nng_aio_finish(aio, 0);
	rest_recycle_job(job);
}

static void
rest_job_cb(void *arg)
{
	rest_job *job = arg;
	nng_aio * aio = job->aio;
	int       rv;

	switch (job->state) {
	case SEND_REQ:
		if ((rv = nng_aio_result(aio)) != 0) {
			rest_http_fatal(job, "send REQ failed: %s", rv);
			return;
		}
		job->msg = NULL;
		// Message was sent, so now wait for the reply.
		nng_aio_set_msg(aio, NULL);
		job->state = RECV_REP;
		nng_ctx_recv(job->ctx, aio);
		break;
	case RECV_REP:
		if ((rv = nng_aio_result(aio)) != 0) {
			rest_http_fatal(job, "recv reply failed: %s", rv);
			return;
		}
		job->msg = nng_aio_get_msg(aio);

		// We got a reply, so give it back to the server.
		http_msg *res_msg = (http_msg *) nng_msg_body(job->msg);

		rv = nng_http_res_copy_data(
		    job->http_res, res_msg->data, res_msg->data_len);

		if (rv != 0) {
			rest_http_fatal(job, "nng_http_res_copy_data: %s", rv);
			return;
		}

		nng_http_res_set_status(job->http_res, res_msg->status);
		if (res_msg->content_type_len > 0) {
			nng_http_res_set_header(job->http_res, "Content-Type",
			    res_msg->content_type);
		}
		if (res_msg->token_len > 0) {
			nng_http_res_set_header(
			    job->http_res, "Cookies", res_msg->token);
		}

		destory_http_msg(res_msg);
		nng_msg_clear(job->msg);
		// Set the output - the HTTP server will send it
		// back to the user agent with a 200 response.
		nng_aio_set_output(job->http_aio, 0, job->http_res);
		nng_aio_finish(job->http_aio, 0);
		job->http_aio = NULL;
		job->http_res = NULL;
		// We are done with the job.
		rest_recycle_job(job);
		return;
	default:
		fatal("bad case", NNG_ESTATE);
		break;
	}
}

// Our rest server just takes the message body, creates a request ID
// for it, and sends it on.  This runs in raw mode, so
void
rest_handle(nng_aio *aio)
{
	struct rest_job *job;
	nng_http_req *   req  = nng_aio_get_input(aio, 0);
	nng_http_conn *  conn = nng_aio_get_input(aio, 2);
	const char *     clen;
	size_t           sz;
	nng_iov          iov;
	int              rv;
	void *           data;

	if ((job = rest_get_job()) == NULL) {
		nng_aio_finish(aio, NNG_ENOMEM);
		return;
	}
	if (((rv = nng_http_res_alloc(&job->http_res)) != 0) ||
	    ((rv = nng_ctx_open(&job->ctx, req_sock)) != 0)) {
		rest_recycle_job(job);
		nng_aio_finish(aio, rv);
		return;
	}

	const char *uri = nng_http_req_get_uri(req);
	debug_msg("get http uri: %s", uri);

	const char *method = nng_http_req_get_method(req);
	debug_msg("get http method: %s", method);

	const char *content_type =
	    nng_http_req_get_header(req, "Content-Type");
	debug_msg("get http header: Content-Type: %s", content_type);

	const char *token = nng_http_req_get_header(req, "Authorization");
	debug_msg("get http header: Authorization: %s", token);

	nng_http_req_get_data(req, &data, &sz);
	job->http_aio = aio;

	http_msg recv_msg = { 0 };

	put_http_msg(&recv_msg, content_type, method, uri, token, data, sz);

	if ((rv = nng_msg_alloc(&job->msg, sizeof(http_msg))) != 0) {
		rest_http_fatal(job, "nng_msg_alloc: %s", rv);
		return;
	}

	memcpy(nng_msg_body(job->msg), &recv_msg, sizeof(http_msg));

	nng_aio_set_msg(job->aio, job->msg);
	job->state = SEND_REQ;
	nng_ctx_send(job->ctx, job->aio);
}

void
rest_start(uint16_t port)
{
	nng_http_server * server;
	nng_http_handler *handler;
	nng_http_handler *handler_file;
	char              rest_addr[128];
	nng_url *         url;
	int               rv;

	if ((rv = nng_mtx_alloc(&job_lock)) != 0) {
		fatal("nng_mtx_alloc", rv);
	}
	job_freelist = NULL;

	// Set up some strings, etc.  We use the port number
	// from the argument list.
	snprintf(rest_addr, sizeof(rest_addr), REST_URL, port);
	if ((rv = nng_url_parse(&url, rest_addr)) != 0) {
		fatal("nng_url_parse", rv);
	}

	// Create the REQ socket, and put it in raw mode, connected to
	// the remote REP server (our inproc server in this case).
	if ((rv = nng_req0_open(&req_sock)) != 0) {
		fatal("nng_req0_open", rv);
	}
	if ((rv = nng_dial(req_sock, INPROC_URL, NULL, NNG_FLAG_NONBLOCK)) !=
	    0) {
		fatal("nng_dial(" INPROC_URL ")", rv);
	}

	// Get a suitable HTTP server instance.  This creates one
	// if it doesn't already exist.
	if ((rv = nng_http_server_hold(&server, url)) != 0) {
		fatal("nng_http_server_hold", rv);
	}

	// Allocate the handler - we use a dynamic handler for REST
	// using the function "rest_handle" declared above.
	rv = nng_http_handler_alloc(&handler, url->u_path, rest_handle);
	if (rv != 0) {
		fatal("nng_http_handler_alloc", rv);
	}

	if ((rv = nng_http_handler_set_method(handler, NULL)) != 0) {
		fatal("nng_http_handler_set_method", rv);
	}

	// We want to collect the body, and we (arbitrarily) limit this to
	// 128KB.  The default limit is 1MB.  You can explicitly collect
	// the data yourself with another HTTP read transaction by disabling
	// this, but that's a lot of work, especially if you want to handle
	// chunked transfers.
	if ((rv = nng_http_handler_collect_body(handler, true, 1024 * 128)) !=
	    0) {
		fatal("nng_http_handler_collect_body", rv);
	}

	rv = nng_http_handler_alloc_directory(&handler_file, "", "./dist");
	if (rv != 0) {
		fatal("nng_http_handler_alloc_file", rv);
	}

	if ((rv = nng_http_handler_set_method(handler_file, "GET")) != 0) {
		fatal("nng_http_handler_set_method", rv);
	}

	if ((rv = nng_http_handler_collect_body(handler_file, true, 1024)) !=
	    0) {
		fatal("nng_http_handler_collect_body", rv);
	}

	if ((rv = nng_http_server_add_handler(server, handler_file)) != 0) {
		fatal("nng_http_handler_add_handler", rv);
	}
	if ((rv = nng_http_server_add_handler(server, handler)) != 0) {
		fatal("nng_http_handler_add_handler", rv);
	}

	if ((rv = nng_http_server_start(server)) != 0) {
		fatal("nng_http_server_start", rv);
	}

	nng_url_free(url);
}

//
// inproc_server - this just is a simple REP server that listens for
// messages, and performs ROT13 on them before sending them.  This
// doesn't have to be in the same process -- it is hear for demonstration
// simplicity only.  (Most likely this would be somewhere else.)  Note
// especially that this uses inproc, so nothing can get to it directly
// from outside the process.
//
void
inproc_server(void *arg)
{
	nng_socket s;
	int        rv;
	nng_msg *  msg;

	if (((rv = nng_rep0_open(&s)) != 0) ||
	    ((rv = nng_listen(s, INPROC_URL, NULL, 0)) != 0)) {
		fatal("unable to set up inproc", rv);
	}
	// This is simple enough that we don't need concurrency.  Plus it
	// makes for an easier demo.
	for (;;) {
		if ((rv = nng_recvmsg(s, &msg, 0)) != 0) {
			fatal("inproc recvmsg", rv);
		}

		http_msg *recv_msg = (http_msg *) nng_msg_body(msg);
		debug_msg("content-type: %.*s",
		    (int) recv_msg->content_type_len, recv_msg->content_type);
		debug_msg("method: %.*s", (int) recv_msg->method_len,
		    recv_msg->method);
		debug_msg(
		    "data: %.*s", (int) recv_msg->data_len, recv_msg->data);

		http_msg res = process_request(recv_msg);

		// response to client
		nng_msg *send_msg;
		nng_msg_alloc(&send_msg, sizeof(http_msg));

		memcpy(nng_msg_body(send_msg), &res, sizeof(http_msg));
		destory_http_msg(recv_msg);
		nng_msg_free(msg);

		if ((rv = nng_sendmsg(s, send_msg, 0)) != 0) {
			fatal("inproc sendmsg", rv);
		}
	}
}

// static void
// log_lock(bool lock, void *udata)
// {
// 	nng_mtx *LOCK = (nng_mtx *) (udata);
// 	if (lock)
// 		nng_mtx_lock(LOCK);
// 	else
// 		nng_mtx_unlock(LOCK);
// }

void
set_global_conf(conf *config)
{
	global_config = config;
}

conf *
get_global_conf(void)
{
	return global_config;
}

void
set_http_server_conf(conf_http_server *conf)
{

	if (conf->username == NULL) {
		conf->username = HTTP_DEFAULT_USER;
	}
	if (conf->password == NULL) {
		conf->password = HTTP_DEFAULT_PASSWORD;
	}

	http_server_conf = conf;
}

conf_http_server *
get_http_server_conf(void)
{
	return http_server_conf;
}

int
start_rest_server(conf *conf)
{
	int rv;

	// 	nng_mtx_alloc(&mtx_log);
	// 	log_set_lock(log_lock, mtx_log);
	// 	log_set_level(LOG_DEBUG);
	// 	logfile = fopen("web_server.log", "a");
	// #if !defined(NOLOG)
	// 	log_set_quiet(true);
	// 	log_add_fp(logfile, LOG_DEBUG);
	// #endif
	rv = nng_thread_create(&inproc_thr, inproc_server, NULL);
	if (rv != 0) {
		fatal("cannot start inproc server", rv);
	}

	uint16_t port = conf->http_server.port ? conf->http_server.port
	                                       : HTTP_DEFAULT_PORT;
	debug_msg(REST_URL, port);
	set_global_conf(conf);
	set_http_server_conf(&conf->http_server);
	rest_start(port);

	return rv;
}

void
stop_rest_server(void)
{
	nng_thread_destroy(inproc_thr);
	// fclose(logfile);
	// nng_mtx_free(mtx_log);
}
