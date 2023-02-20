#if defined(SUPP_RULE_ENGINE)
#include "rule_ctrl.h"
#include <stdint.h>
#include "nng/nng.h"
#include "nng/supplemental/http/http.h"
#include "nng/supplemental/nanolib/cJSON.h"
#include "nng/supplemental/nanolib/conf.h"
#include "nng/supplemental/util/options.h"
#include "nng/supplemental/nanolib/utils.h"


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
	OPT_ID,
	OPT_SQL,
	OPT_ENABLED,
	OPT_ACTIONS
};

static nng_optspec cmd_opts[] = {
	{ .o_name = "help", .o_short = 'h', .o_val = OPT_HELP },
	{ .o_name = "list", .o_short = 'l', .o_val = OPT_LIST },
	{ .o_name = "show", .o_short = 's', .o_val = OPT_SHOW },
	{ .o_name = "create", .o_short = 'c', .o_val = OPT_CREATE },
	{ .o_name = "update", .o_short = 'u', .o_val = OPT_UPDATE },
	{ .o_name = "delete", .o_short = 'd', .o_val = OPT_DELETE },
	{ .o_name = "id", .o_short = 'i', .o_val = OPT_ID, .o_arg = true },
	{ .o_name = "sql", .o_val = OPT_SQL, .o_arg = true },
	{ .o_name = "actions", .o_val = OPT_ACTIONS, .o_arg = true },
	{ .o_name    = "enabled",
	    .o_short = 'e',
	    .o_val   = OPT_ENABLED,
	    .o_arg   = true },
	{ .o_name = NULL, .o_val = 0 },
};

static char help_info[] =
    "Usage: nanomq_cli rules [command] [<sql>] [<actions>] [-i [<id>]]\n"
    "                        [-e [<enabled>]]\n\n"
    "  -c, --create          Create a rule \n"
    "  -u, --update          Update a rule \n"
    "  -l, --list            List all rules \n"
    "  -s, --show            Show a rule \n"
    "  -d, --delete          Delete a rule \n"
	"  -i, --id              The rule id\n"
  	"  -e, --enabled         'true' or 'false' to enable or disable the rule\n"
	"                        [default: true]\n"
	"  --sql                 Filter Condition SQL\n"
	"  --actions             < Action List in JSON format: [{\"name\":\n"
    "                        <action_name>, \"params\": {<key>: <value>}}]\n";


// TODO 1. add ip port
// TODO 2. parse return value.

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

	char new_url[64] = { 0 };
	if (0 != id) {
		snprintf(new_url, 64, "%s/rule:%d", ori_url, id);
	} else {
		snprintf(new_url, 64, "%s", ori_url);
	}
	

	if (((rv = nng_url_parse(&url, new_url)) != 0) ||
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
	if (payload) {
		nng_http_req_set_data(req, payload, strlen(payload));
	}
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
		nng_fatal("nng_aio_result", rv);
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
		nng_fatal("nng_aio_result", rv);
	}

	cJSON *jso = cJSON_ParseWithLength(data, len);
	cJSON *eles = NULL;
	// printf("%.*s\n", (int) len, (char*) data);

	if (NULL != (eles = cJSON_GetObjectItem(jso, "data"))) {
		if (cJSON_IsObject(eles)) {
			char *val = cJSON_PrintUnformatted(eles);
			puts(val);
			cJSON_free(val);
		} else {
			cJSON *ele = NULL;
			cJSON_ArrayForEach(ele, eles)
			{
				if (ele) {
					char *val =
					    cJSON_PrintUnformatted(ele);
					puts(val);
					cJSON_free(val);
				}
			}
		}

	} else {
		printf("%.*s\n", (int) len, (char*) data);
	}

	cJSON_Delete(jso);

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
	if (data) {
		nng_free(data, len);
	}
}


int
rules_parse_opts(int argc, char **argv)
{
	int   idx = 1;
	char *arg;
	int   val;
	int   rv;

	typedef enum {
		RULE_CREATE,
		RULE_DELETE,
		RULE_UPDATE,
		RULE_SHOW,
		RULE_LIST,
		RULE_NONE
	}  rule_cmd;

	rule_cmd cmd          = RULE_NONE;
	uint32_t id           = 0;
	uint8_t  enabled      = 0;
	char     sql[128]     = { 0 };
	char     actions[512] = { 0 };

	while ((rv = nng_opts_parse(
	            argc - 1, argv + 1, cmd_opts, &val, &arg, &idx)) == 0) {
		switch (val) {
		case OPT_HELP:
			printf("%s", help_info);
			exit(0);
			break;
		case OPT_CREATE:
			cmd = RULE_CREATE;
			break;
		case OPT_UPDATE:
			cmd = RULE_UPDATE;
			break;
		case OPT_LIST:
			cmd = RULE_LIST;
			break;
		case OPT_SHOW:
			cmd = RULE_SHOW;
			break;
		case OPT_DELETE:
			cmd = RULE_DELETE;
			break;
		case OPT_ID:
			id = atoi(arg);
			break;
		case OPT_SQL:
			snprintf(sql, 128, "%s", arg);
			break;
		case OPT_ENABLED:
			if (!strcmp("true", arg)) {
				enabled = 2;
			} else if (!strcmp("false", arg)) {
				enabled = 1;
			}
			break;
		case OPT_ACTIONS:
			snprintf(actions, 512, "{ \"actions\":%s }", arg);
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

	char *dest = NULL;
	cJSON *jso = NULL; //cJSON_CreateObject();
	switch (cmd)
	{
	case RULE_CREATE:
		if (0 != strlen(actions)) {
			jso = cJSON_Parse(actions);
			if (!cJSON_IsObject(jso)) {
				puts("params json format illegal.");
				return -1;
			}
		} else {
			puts("Error: create rule need set actions.");
			printf("%s", help_info);
			return -1;

		}

		if (enabled != 0) {
			cJSON_AddBoolToObject(jso, "enabled", enabled-1);
		}

		if (0 != strlen(sql)) {
			cJSON_AddStringToObject(jso, "rawsql", sql);
		} else {
			puts("Error: create rule need set sql.");
			printf("%s", help_info);

		}
		dest = cJSON_PrintUnformatted(jso);
		send_http("POST", 0, dest);
		cJSON_free(dest);
		cJSON_Delete(jso);
		break;
	case RULE_UPDATE:
		if (0 == id) {
			puts("Error: update rule need set id.");
			printf("%s", help_info);
			return -1;
		}

		if (0 == strlen(actions) && enabled == 0 && 0 == strlen(sql)) {
			puts("Error: update rule need set actions or enable status or sql.");
			printf("%s", help_info);
			return -1;

		}

		if (0 != strlen(actions)) {
			jso = cJSON_Parse(actions);
		} else {
			jso = cJSON_CreateObject();
		}

		if (enabled != 0) {
			cJSON_AddBoolToObject(jso, "enabled", enabled-1);
		}

		if (0 != strlen(sql)) {
			cJSON_AddStringToObject(jso, "rawsql", sql);
		}

		dest = cJSON_PrintUnformatted(jso);
		send_http("PUT", id, dest);
		cJSON_free(dest);
		cJSON_Delete(jso);
		break;
	case RULE_DELETE:
		if (0 == id) {
			puts("Error: delete rule need set id.");
			printf("%s", help_info);
			return -1;
		}
		send_http("DELETE", id, NULL);
		break;
	case RULE_SHOW:
		if (0 == id) {
			puts("Error: show specify rule need set id.");
			printf("%s", help_info);
			return -1;
		}
		send_http("GET", id, NULL);
		break;
	case RULE_LIST:
		send_http("GET", 0, NULL);
		break;
	case RULE_NONE:
		puts("Error: A command is needed (create/update/delete/show/list).");
		printf("%s", help_info);
		break;
	
	default:
		break;
	}

	return rv == -1;
}

int rules_start(int argc, char **argv)
{
	if (2 >= argc) {
		printf("%s", help_info);
		return -1;
	}
	rules_parse_opts(argc, argv);
	return 0;
}


int
rules_dflt(int argc, char **argv)
{
	printf("%s", help_info);
	return 0;
}

#endif