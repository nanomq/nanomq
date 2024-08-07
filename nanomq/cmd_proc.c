//
// Copyright 2023 NanoMQ Team, Inc. <jaylin@emqx.io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "include/cmd_proc.h"
#include "include/conf_api.h"
#include "include/nanomq.h"
#include "nng/protocol/reqrep0/rep.h"
#include "nng/protocol/reqrep0/req.h"
#include "nng/supplemental/nanolib/cJSON.h"
#include "nng/supplemental/nanolib/utils.h"
#include "nng/supplemental/util/platform.h"

struct cmd_work {
	enum {
		INIT,
		RECV,
		WAIT,
		SEND, // Actions after sending msg
	} state;
	nng_aio *aio;
	nng_msg *msg;
	nng_ctx  ctx;
	conf *   config;
};

static int
handle_recv(const char *msg, size_t msg_len, conf *config, char **err_msg)
{
	cJSON *obj = cJSON_ParseWithLength(msg, msg_len);
	cJSON *item;
	int    rv        = 0;
	char * conf_file = NULL;
	char * cmd       = NULL;
	conf  *new_conf  = NULL;

	getStringValue(obj, item, "cmd", cmd, rv);

	if (rv != 0 || nng_strcasecmp(cmd, "reload") != 0) {
		*err_msg = nng_strdup("reload failed, invalid command!");
		goto err;
	}
	getStringValue(obj, item, "conf_file", conf_file, rv);

	if (rv != 0 && config->conf_file == NULL) {
		*err_msg = nng_strdup("reload failed, conf_file is not specified!");
		goto err;
	}

	if (conf_file != NULL && nano_file_exists(conf_file) == false) {
		*err_msg = nng_strdup("reload failed, conf_file does not exist!");
		goto err;
	}

	new_conf = nng_alloc(sizeof(conf));
	if (new_conf == NULL) {
		*err_msg = nng_strdup("reload failed, alloc memory failed!");
		goto err;
	}

	conf_init(new_conf);
	new_conf->conf_file = conf_file != NULL
	    ? nng_strdup(conf_file)
	    : nng_strdup(config->conf_file);

	int conf_type = 2;
	getNumberValue(obj, item, "conf_type", conf_type, rv);
	switch (conf_type) {
	case 2: /* OPT_HOCONFILE */
		conf_parse_ver2(new_conf);
		break;
	case 3: /* OPT_CONFILE */
		conf_parse(new_conf);
		break;
	default:
		*err_msg = nng_strdup("reload failed, wrong conf type!");
		goto err;
	}

	reload_basic_config(config, new_conf);
	reload_sqlite_config(&config->sqlite, &new_conf->sqlite);
	reload_auth_config(&config->auths, &new_conf->auths);
	reload_log_config(config, new_conf);


	conf_fini(new_conf);
	cJSON_Delete(obj);
	return 0;

err:
	conf_fini(new_conf);
	cJSON_Delete(obj);
	return -1;
}

void
cmd_server_cb(void *arg)
{
	struct cmd_work *work = arg;
	nng_msg *        msg;
	int              rv;

	switch (work->state) {
	case INIT:
		work->state = RECV;
		nng_ctx_recv(work->ctx, work->aio);
		break;
	case RECV:
		if ((rv = nng_aio_result(work->aio)) != 0) {
			NANO_NNG_FATAL("nng_recv_aio", rv);
		}
		msg       = nng_aio_get_msg(work->aio);
		char *cmd = (char *) nng_msg_body(msg);
		log_debug("recv cmd : %s", cmd);
		char *resp = NULL;

		if (handle_recv(cmd, nng_msg_len(msg), work->config, &resp) ==
		    0) {
			resp = nng_strdup("reload succeed!");
		} else {
			if (resp == NULL) {
				resp = nng_strdup("reload failed!");
			}
		}

		nng_msg_clear(msg);
		nng_msg_append(msg, resp, strlen(resp) + 1);
		nng_strfree(resp);

		log_debug("send resp : %s", (char *) nng_msg_body(msg));

		nng_aio_set_msg(work->aio, msg);
		work->msg   = NULL;
		work->state = SEND;
		nng_ctx_send(work->ctx, work->aio);
		break;

	case SEND:
		if ((rv = nng_aio_result(work->aio)) != 0) {
			nng_msg_free(work->msg);
			NANO_NNG_FATAL("nng_send_aio", rv);
		}
		work->state = RECV;
		nng_ctx_recv(work->ctx, work->aio);
		break;

	default:
		NANO_NNG_FATAL("bad state!", NNG_ESTATE);
		break;
	}
}

cmd_work *
alloc_cmd_work(nng_socket sock, conf *config)
{
	struct cmd_work *w;
	int              rv;

	if ((w = nng_alloc(sizeof(*w))) == NULL) {
		NANO_NNG_FATAL("nng_alloc", NNG_ENOMEM);
	}
	if ((rv = nng_aio_alloc(&w->aio, cmd_server_cb, w)) != 0) {
		NANO_NNG_FATAL("nng_aio_alloc", rv);
	}
	if ((rv = nng_ctx_open(&w->ctx, sock)) != 0) {
		NANO_NNG_FATAL("nng_ctx_open", rv);
	}
	w->config = config;
	w->state  = INIT;
	return (w);
}

#if 0
// The server runs forever.
static void
server(void *arg)
{
	conf *           config = (conf *) arg;
	nng_socket       sock;
	struct cmd_work *works[CMD_PROC_PARALLEL];
	int              rv;
	int              i;
	const char *     url = CMD_IPC_URL;

	/*  Create the socket. */
	rv = nng_rep0_open(&sock);
	if (rv != 0) {
		NANO_NNG_FATAL("nng_rep0_open", rv);
	}

	for (i = 0; i < CMD_PROC_PARALLEL; i++) {
		works[i] = alloc_cmd_work(sock, config);
	}

	if ((rv = nng_listen(sock, url, NULL, 0)) != 0) {
		NANO_NNG_FATAL("nng_listen", rv);
	}

	for (i = 0; i < CMD_PROC_PARALLEL; i++) {
		cmd_server_cb(works[i]); // this starts them going (INIT state)
	}

	for (;;) {
		nng_msleep(3600000); // neither pause() nor sleep() portable
	}
}

void
start_cmd_server(conf *config)
{
	nng_thread *t;
	nng_thread_create(&t, server, config);
}

#endif

static void
client(const char *cmd, const char *url)
{
	nng_socket  sock;
	nng_dialer  dialer;
	int         rv;
	char *      buf = NULL;
	size_t      sz  = 0;

	if ((rv = nng_req0_open(&sock)) != 0) {
		NANO_NNG_FATAL("nng_req0_open", rv);
	}
	if ((rv = nng_dialer_create(&dialer, sock, url)) != 0) {
		NANO_NNG_FATAL("nng_dialer_create", rv);
	}
	nng_socket_set_ms(sock, NNG_OPT_REQ_RESENDTIME, 2000);
	if ((rv = nng_dialer_start(dialer, NNG_FLAG_ALLOC)) != 0) {
		NANO_NNG_FATAL("nng_dialer_start", rv);
	}

	if ((rv = nng_send(sock, (void *) cmd, strlen(cmd) + 1, 0)) != 0) {
		NANO_NNG_FATAL("nng_send", rv);
	}

	if ((rv = nng_recv(sock, &buf, &sz, NNG_FLAG_ALLOC)) != 0) {
		NANO_NNG_FATAL("nng_recv", rv);
	}
	if (sz > 0) {
		printf("%.*s\n", (int) sz, (const char *) buf);
	} else {
		printf("no response from broker\n");
	}

	nng_free(buf, sz);
	nng_close(sock);
}

char *
encode_client_cmd(const char *conf_file, int type)
{
	cJSON *obj = cJSON_CreateObject();
	cJSON_AddStringToObject(obj, "cmd", "reload");
	cJSON_AddStringToObject(obj, "conf_file", conf_file);
	cJSON_AddNumberToObject(obj, "conf_type", type);
	char *cmd = cJSON_PrintUnformatted(obj);
	cJSON_Delete(obj);
	return cmd;
}

void
start_cmd_client(const char *cmd, const char *url)
{
	client(cmd, url);
}
