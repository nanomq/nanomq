// This is a test only Scenario for advanced features of NanoMQ, like webhook, etc.
#define INPROC_TEST_URL "inproc://test"
#define REST_TEST_URL "http://0.0.0.0:%u/hook"

int webhook_msg_cnt = 0; // this is a silly signal to indicate whether the webhook tests pass

// This is a silly demo for test -- it listens on port 8888 (or $PORT if present),
// and accepts HTTP POST requests at /test
//
// These requests are converted into an NNG REQ message, and sent to an
// NNG REP server (builtin inproc_server, for test purposes only).
// The reply is obtained from the server, and sent back to the client via
// the HTTP server framework.

#include <nng/nng.h>
#include <nng/protocol/reqrep0/rep.h>
#include <nng/protocol/reqrep0/req.h>
#include <nng/supplemental/http/http.h>
#include <nng/supplemental/util/platform.h>
#include <nng/supplemental/nanolib/conf.h>
#include "include/broker.h"
#include "include/rest_api.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>

// This server acts as a proxy.  We take HTTP POST requests, convert them to
// REQ messages, and when the reply is received, send the reply back to
// the original HTTP client.
//
// The state flow looks like:
//
// 1. Receive HTTP request & headers
// 2. Receive HTTP request (POST) data
// 3. Send POST payload as REQ body
// 4. Receive REP reply (including payload)
// 5. Return REP message body to the HTTP server (which forwards to client)
// 6. Restart at step 1.
//
// The above flow is pretty linear, and so we use contexts (nng_ctx) to
// obtain parallelism.

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

nng_socket req_sock;

// We maintain a queue of free jobs.  This way we don't have to
// deallocate them from the callback; we just reuse them.
nng_mtx * job_lock;
rest_job *job_freelist;

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
		if (nng_msg_len(job->msg) > 0) {
			// We got a reply, so give it back to the server.
			rv = nng_http_res_copy_data(job->http_res,
			    nng_msg_body(job->msg), nng_msg_len(job->msg));
			if (strcmp(nng_msg_body(job->msg), "ok") == 0) {
				nng_http_res_set_status(
				    job->http_res, NNG_HTTP_STATUS_OK);
			} else {
				nng_http_res_set_status(job->http_res,
				    NNG_HTTP_STATUS_UNAUTHORIZED);
			}
			if (rv != 0) {
				rest_http_fatal(
				    job, "nng_http_res_copy_data: %s", rv);
				return;
			}
		} else {
			nng_http_res_set_status(
			    job->http_res, NNG_HTTP_STATUS_BAD_REQUEST);
		}
		// if (nng_clock() % 2 == 0) {
		// 	nng_http_res_set_status(job->http_res, 404);
		// }
		// Set the output - the HTTP server will send it back to the
		// user agent with a 200 response.
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
static void
rest_handle(nng_aio *aio)
{
	struct rest_job *job;
	nng_http_req *   req  = nng_aio_get_input(aio, 0);
	nng_http_conn *  conn = nng_aio_get_input(aio, 2);
	const char *     clen;
	size_t           sz = 0;
	nng_iov          iov;
	int              rv;
	void *           data;

	// printf("%s\n", __FUNCTION__);
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
	const char *method = nng_http_req_get_method(req);
	const char *token = nng_http_req_get_header(req, "TOKEN");
	const char *content_type =
	    nng_http_req_get_header(req, "content-type");
	// printf("\r\n");
	// printf("uri: [%s]\n", uri);
	// printf("method: [%s]\n", method);
	// printf("header: token: [%s]\n", token);
	// printf("header: content-type: [%s]\n", content_type);

	if (strcasecmp(method, "get") == 0) {
		data = strchr(uri, '?');
		if (data) {

			data++;
			sz = strlen(data) + 1;
		}
	} else if (strcasecmp(method, "post") == 0) {
		nng_http_req_get_data(req, &data, &sz);
	} else {
		rest_http_fatal(job, "method not supported:%s", method);
	}

	job->http_aio = aio;

	if ((rv = nng_msg_alloc(&job->msg, sz)) != 0) {
		rest_http_fatal(job, "nng_msg_alloc: %s", rv);
		return;
	} else if (sz == 0) {
		rest_http_fatal(job, "%s", NNG_HTTP_STATUS_NO_CONTENT);
	}

	memcpy(nng_msg_body(job->msg), data, sz);
	nng_aio_set_msg(job->aio, job->msg);
	job->state = SEND_REQ;
	nng_ctx_send(job->ctx, job->aio);
}

void
test_rest_start(uint16_t port)
{
	nng_http_server * server;
	nng_http_handler *handler;
	char              rest_addr[128];
	nng_url *         url;
	int               rv;

	if ((rv = nng_mtx_alloc(&job_lock)) != 0) {
		fatal("nng_mtx_alloc", rv);
	}
	job_freelist = NULL;

	// Set up some strings, etc.  We use the port number
	// from the argument list.
	snprintf(rest_addr, sizeof(rest_addr), REST_TEST_URL, port);
	if ((rv = nng_url_parse(&url, rest_addr)) != 0) {
		fatal("nng_url_parse", rv);
	}

	// Create the REQ socket, and put it in raw mode, connected to
	// the remote REP server (our inproc server in this case).
	if ((rv = nng_req0_open(&req_sock)) != 0) {
		fatal("nng_req0_open", rv);
	}
	if ((rv = nng_dial(req_sock, INPROC_TEST_URL, NULL, NNG_FLAG_NONBLOCK)) !=
	    0) {
		fatal("nng_dial(" INPROC_TEST_URL ")", rv);
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

	if ((rv = nng_http_handler_set_tree(handler)) != 0) {
		fatal("nng_http_handler_set_tree", rv);
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
test_inproc_server(void *arg)
{
	nng_socket s;
	int        rv;
	nng_msg *  msg;

	if (((rv = nng_rep0_open(&s)) != 0) ||
	    ((rv = nng_listen(s, INPROC_TEST_URL, NULL, 0)) != 0)) {
		fatal("unable to set up inproc", rv);
	}
	// This is simple enough that we don't need concurrency.  Plus it
	// makes for an easier demo.
	for (;;) {
		if ((rv = nng_recvmsg(s, &msg, 0)) != 0) {
			fatal("inproc recvmsg", rv);
		}
		// char *body = nng_msg_body(msg);
		// printf("\tReceived: %s\n", (char *) body);
		nng_msg_free(msg);
		webhook_msg_cnt++;

		char *res = "OK";
		if ((rv = nng_send(s, res, strlen(res), 0)) != 0) {
			fatal("inproc sendmsg", rv);
		}
	}
}

conf*
get_dflt_conf()
{
	conf               *nanomq_conf;
	if ((nanomq_conf = nng_zalloc(sizeof(conf))) == NULL) {
		fprintf(stderr,
		    "Cannot allocate storge for configuration, quit\n");
		exit(EXIT_FAILURE);
	}
	conf_init(nanomq_conf);
	nanomq_conf->url                    = "nmq-tcp://0.0.0.0:1881";
	nanomq_conf->conf_file              = NULL;
	nanomq_conf->daemon                 = false;
	nanomq_conf->num_taskq_thread       = 1;
	nanomq_conf->max_taskq_thread       = 1;
	nanomq_conf->parallel               = 10;
	nanomq_conf->property_size          = 32;
	nanomq_conf->max_packet_size        = 1024;
	nanomq_conf->client_max_packet_size = 1024;
	nanomq_conf->msq_len                = 32;
	nanomq_conf->qos_duration           = 2;

	nanomq_conf->sqlite.enable      = false;
	nanomq_conf->tls.enable         = false;
	nanomq_conf->websocket.enable   = false;
	nanomq_conf->http_server.enable = false;
	nanomq_conf->web_hook.enable    = false;
	return nanomq_conf;
}

conf*
get_webhook_conf()
{
	conf *nanomq_conf = get_dflt_conf();
	conf_http_header   *header;
	conf_web_hook_rule *webhook_rule;

	// conf for webhook
	nanomq_conf->web_hook.enable         = true;
	nanomq_conf->web_hook.url            = "http://0.0.0.0:8888/hook";
	nanomq_conf->web_hook.encode_payload = plain;
	nanomq_conf->web_hook.pool_size      = 32;

	// set up webhook headers
	nanomq_conf->web_hook.header_count = 1;
	nanomq_conf->web_hook.headers = realloc(nanomq_conf->web_hook.headers,
	    nanomq_conf->web_hook.header_count * sizeof(conf_http_header *));
		
	header                        = calloc(1, sizeof(conf_http_header));
	header->key                   = "content-type";
	header->value                 = "application/json";
	nanomq_conf->web_hook.headers[0] = header;

	// set up webhook rules
	nanomq_conf->web_hook.rule_count = 5;
	nanomq_conf->web_hook.rules      = realloc(nanomq_conf->web_hook.rules,
	         nanomq_conf->web_hook.rule_count * sizeof(conf_web_hook_rule *));

	webhook_rule                   = calloc(1, sizeof(conf_web_hook_rule));
	webhook_rule->event            = MESSAGE_PUBLISH;
	webhook_rule->rule_num         = 1;
	webhook_rule->action           = "on_message_publish";
	nanomq_conf->web_hook.rules[0] = webhook_rule;
	webhook_rule                   = calloc(1, sizeof(conf_web_hook_rule));
	webhook_rule->event            = CLIENT_CONNECT;
	webhook_rule->rule_num         = 1;
	webhook_rule->action           = "on_client_connect";
	nanomq_conf->web_hook.rules[1] = webhook_rule;
	webhook_rule                   = calloc(1, sizeof(conf_web_hook_rule));
	webhook_rule->event            = CLIENT_CONNACK;
	webhook_rule->rule_num         = 1;
	webhook_rule->action           = "on_client_connack";
	nanomq_conf->web_hook.rules[2] = webhook_rule;
	webhook_rule                   = calloc(1, sizeof(conf_web_hook_rule));
	webhook_rule->event            = CLIENT_CONNECTED;
	webhook_rule->rule_num         = 1;
	webhook_rule->action           = "on_client_connected";
	nanomq_conf->web_hook.rules[3] = webhook_rule;
	webhook_rule                   = calloc(1, sizeof(conf_web_hook_rule));
	webhook_rule->event            = CLIENT_DISCONNECTED;
	webhook_rule->rule_num         = 1;
	webhook_rule->action           = "on_client_disconnected";
	nanomq_conf->web_hook.rules[4] = webhook_rule;

	return nanomq_conf;
}

conf *
get_test_conf()
{
	// get conf from file
	conf *nmq_conf  = nng_zalloc(sizeof(conf));
	char *conf_path = "../../../nanomq/tests/nanomq_test.conf";
	conf_init(nmq_conf);
	nmq_conf->conf_file = conf_path;
	conf_parse_ver2(nmq_conf);

	return nmq_conf;
}
