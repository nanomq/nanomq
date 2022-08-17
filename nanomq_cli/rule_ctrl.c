#if defined(SUPP_RULE_ENGINE)
#include "rule_ctrl.h"
#include "nng/nng.h"
#include "nng/supplemental/http/http.h"
#include "nng/supplemental/nanolib/cJSON.h"
#include "nng/supplemental/nanolib/conf.h"
#include "nng/supplemental/util/options.h"

void
fatal(int rv)
{
	fprintf(stderr, "%s\n", nng_strerror(rv));
	exit(1);
}


struct work {
	enum { INIT, RECV, WAIT, SEND } state;
	nng_aio *aio;
	nng_msg *msg;
	nng_ctx  ctx;
};

enum options {
	OPT_HELP = 1,
	OPT_CREATE,
	OPT_UPDATE,
	OPT_LIST,
	OPT_SHOW,
	OPT_DELETE,
};

static nng_optspec cmd_opts[] = {
	{ .o_name = "help", .o_short = 'h', .o_val = OPT_HELP },
	{ .o_name = "list", .o_short = 'l', .o_val = OPT_LIST },
	{ .o_name = "show", .o_short = 's', .o_val = OPT_SHOW, .o_arg = true },
	{ .o_name    = "create",
	    .o_short = 'c',
	    .o_val   = OPT_CREATE,
	    .o_arg   = true },
	{ .o_name    = "update",
	    .o_short = 'u',
	    .o_val   = OPT_UPDATE,
	    .o_arg   = true },
	{ .o_name    = "delete",
	    .o_short = 'd',
	    .o_val   = OPT_DELETE,
	    .o_arg   = true },
	{ .o_name = NULL, .o_val = 0 },
};

static char help_info[] =
    "Usage: nanomq_cli rules [--action <rule>]\n\n"
    "  --create <Rule>                Create a rule \n"
    "  --update <RuleId>              Update a rule \n"
    "  --list                         List all rules \n"
    "  --show <RuleId>                Show a rule \n"
    "  --delete <RuleId>              Delete a rule \n";

static void
send_http(char *method, int id, char *payload)
{
	nng_http_client *client = NULL;
	nng_http_conn *  conn   = NULL;
	nng_url *        url    = NULL;
	nng_aio *        aio    = NULL;
	nng_http_req *   req    = NULL;
	nng_http_res *   res    = NULL;
	char *ori_url = "http://localhost:8081/api/v4/rules";
	int              rv;
	const char *     hdr;
	int              len;
	void *           data;
	nng_iov          iov;


	if (((rv = nng_url_parse(&url, ori_url)) != 0) ||
	    ((rv = nng_http_client_alloc(&client, url)) != 0) ||
	    ((rv = nng_http_req_alloc(&req, url)) != 0) ||
	    ((rv = nng_http_res_alloc(&res)) != 0) ||
	    ((rv = nng_aio_alloc(&aio, NULL, NULL)) != 0)) {
		printf("init failed: %s\n", nng_strerror(rv));
		goto out;
	}

	// Start connection process...
	nng_aio_set_timeout(aio, 1000);
	nng_http_client_connect(client, aio);

	// Wait for it to finish.
	// TODO It could cause some problems.
	nng_aio_wait(aio);
	if ((rv = nng_aio_result(aio)) != 0) {
		printf("Connect failed: %s\n", nng_strerror(rv));
		nng_aio_finish_sync(aio, rv);
		goto out;
	}

	// Get the connection, at the 0th output.
	conn = nng_aio_get_output(aio, 0);


	// char pass_user[] = "admin:public";

	// base64_encode()

	nng_http_req_add_header(req, "Authorization", "Basic YWRtaW46cHVibGlj");

	nng_http_req_set_method(req, method);
	nng_http_req_set_data(req, payload, strlen(payload));
	nng_http_conn_write_req(conn, req, aio);
	nng_aio_set_timeout(aio, 1000);
	nng_aio_wait(aio);


	if ((rv = nng_aio_result(aio)) != 0) {
		printf("Write req failed: %s\n", nng_strerror(rv));
		nng_aio_finish_sync(aio, rv);
		goto out;
	}

	nng_http_conn_read_res(conn, res, aio);
	nng_aio_wait(aio);

	if ((rv = nng_aio_result(aio)) != 0) {
		fatal(rv);
	}

	if (nng_http_res_get_status(res) != NNG_HTTP_STATUS_OK) {
		fprintf(stderr, "HTTP Server Responded: %d %s\n",
		    nng_http_res_get_status(res),
		    nng_http_res_get_reason(res));
	}

	// This only supports regular transfer encoding (no Chunked-Encoding,
	// and a Content-Length header is required.)
	if ((hdr = nng_http_res_get_header(res, "Content-Length")) == NULL) {
		fprintf(stderr, "Missing Content-Length header.\n");
		exit(1);
	}

	len = atoi(hdr);
	if (len == 0) {
		return;
	}

	// Allocate a buffer to receive the body data.
	data = nng_alloc(len);

	// Set up a single iov to point to the buffer.
	iov.iov_len = len;
	iov.iov_buf = data;

	// Following never fails with fewer than 5 elements.
	nng_aio_set_iov(aio, 1, &iov);

	// Now attempt to receive the data.
	nng_http_conn_read_all(conn, aio);

	// Wait for it to complete.
	nng_aio_wait(aio);

	if ((rv = nng_aio_result(aio)) != 0) {
		fatal(rv);
	}

	printf("%.*s\n", (int) len, (char*) data);



out:
	if (url) {
		nng_url_free(url);
	}
	if (conn) {
		nng_http_conn_close(conn);
	}
	if (client) {
		nng_http_client_free(client);
	}
	if (req) {
		nng_http_req_free(req);
	}
	if (res) {
		nng_http_res_free(res);
	}
	if (aio) {
		nng_aio_free(aio);
	}
}


int
rules_parse_opts(int argc, char **argv)
{
	int   idx = 1;
	char *arg;
	int   val;
	int   rv;

	while ((rv = nng_opts_parse(argc, argv, cmd_opts, &val, &arg, &idx)) ==
	    0) {
		switch (val) {
		case OPT_HELP:
			printf("%s", help_info);
			exit(0);
			break;
		case OPT_CREATE:
			cJSON *jso = cJSON_Parse(arg);
			if (!cJSON_IsObject(jso)) {
				puts("Params json format illegal");
				return -1;
			}
			send_http("POST", 0, arg);
			break;
		case OPT_UPDATE:
			puts(arg);
			break;
		case OPT_LIST:
			puts("list");
			break;
		case OPT_SHOW:
			puts(arg);
			break;
		case OPT_DELETE:
			puts(arg);
			break;
		default:
			break;
		}
	}

	switch (rv) {
	case NNG_EINVAL:
		fprintf(stderr,
		    "Option %s is invalid.\nTry 'nanomq_cli rules --help' for "
		    "more information.\n",
		    argv[idx]);
		break;
	case NNG_EAMBIGUOUS:
		fprintf(stderr,
		    "Option %s is ambiguous (specify in full).\nTry 'nanomq_cli "
		    "rules --help' for more information.\n",
		    argv[idx]);
		break;
	case NNG_ENOARG:
		fprintf(stderr,
		    "Option %s requires argument.\nTry 'nanomq_cli rules "
		    "--help' "
		    "for more information.\n",
		    argv[idx]);
		break;
	default:
		break;
	}

	return rv == -1;
}

int rules_start(int argc, char **argv)
{
	// printf("%s", help_info);
	rules_parse_opts(argc, argv);
	// conf_gateway_parse(conf);
	// if (-1 != gateway_conf_check_and_set(conf)) {
	// 	zmq_gateway(conf);
	// }
	return 0;
}


int
rules_dflt(int argc, char **argv)
{
	printf("%s", help_info);
	return 0;
}

#endif