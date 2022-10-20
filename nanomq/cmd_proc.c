#include "include/cmd_proc.h"
#include "include/conf_api.h"
#include "nng/protocol/reqrep0/rep.h"
#include "nng/protocol/reqrep0/req.h"
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

#define CMD_PROC_PARALLEL 2

static void
fatal(const char *func, int rv)
{
	fprintf(stderr, "%s: %s\n", func, nng_strerror(rv));
	exit(1);
}

static int
handle_reload(conf *config)
{
	if (config->conf_file != NULL) {
		conf *new_conf = nng_alloc(sizeof(conf));
		conf_init(new_conf);
		new_conf->conf_file = nng_strdup(config->conf_file);
		conf_parse(new_conf);

		reload_basic_config(config, new_conf);
		reload_sqlite_config(&config->sqlite, &new_conf->sqlite);
		reload_auth_config(&config->auths, &new_conf->auths);

		conf_fini(new_conf);
		return 0;
	} else {
		log_error("no config file to reload");
		return 1;
	}
}

static void
server_cb(void *arg)
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
			fatal("nng_recv_aio", rv);
		}
		msg         = nng_aio_get_msg(work->aio);
		work->msg   = msg;
		work->state = WAIT;
		nng_sleep_aio(1, work->aio);
		break;
	case WAIT:
		msg       = work->msg;
		char *cmd = (char *) nng_msg_body(msg);
		log_debug("recv cmd : %s", cmd);
		char *resp = NULL;
		if (strcmp(cmd, "reload") == 0) {
			log_debug("reload config");
			if (handle_reload(work->config) == 0) {
				resp = nng_strdup("reload succeed");
			} else {
				resp = nng_strdup(
				    "no configuration file, reload failed");
			}
		} else {
			resp = nng_strdup("invalid command");
		}
		nng_msg_clear(msg);
		nng_msg_append(msg, resp, strlen(resp) + 1);

		log_debug("send resp : %s", (char *) nng_msg_body(msg));

		nng_aio_set_msg(work->aio, msg);
		work->msg   = NULL;
		work->state = SEND;
		nng_ctx_send(work->ctx, work->aio);
		nng_strfree(resp);
		break;

	case SEND:
		if ((rv = nng_aio_result(work->aio)) != 0) {
			nng_msg_free(work->msg);
			fatal("nng_send_aio", rv);
		}
		work->state = RECV;
		nng_ctx_recv(work->ctx, work->aio);
		break;

	default:
		fatal("bad state!", NNG_ESTATE);
		break;
	}
}

static struct cmd_work *
alloc_work(nng_socket sock, conf *config)
{
	struct cmd_work *w;
	int              rv;

	if ((w = nng_alloc(sizeof(*w))) == NULL) {
		fatal("nng_alloc", NNG_ENOMEM);
	}
	if ((rv = nng_aio_alloc(&w->aio, server_cb, w)) != 0) {
		fatal("nng_aio_alloc", rv);
	}
	if ((rv = nng_ctx_open(&w->ctx, sock)) != 0) {
		fatal("nng_ctx_open", rv);
	}
	w->config = config;
	w->state  = INIT;
	return (w);
}

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
		fatal("nng_rep0_open", rv);
	}

	for (i = 0; i < CMD_PROC_PARALLEL; i++) {
		works[i] = alloc_work(sock, config);
	}

	if ((rv = nng_listen(sock, url, NULL, 0)) != 0) {
		fatal("nng_listen", rv);
	}

	for (i = 0; i < CMD_PROC_PARALLEL; i++) {
		server_cb(works[i]); // this starts them going (INIT state)
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

static void
client(const char *cmd)
{
	nng_socket  sock;
	nng_dialer  dialer;
	int         rv;
	nng_msg *   msg;
	char *      buf = NULL;
	size_t      sz  = 0;
	const char *url = CMD_IPC_URL;

	if ((rv = nng_req0_open(&sock)) != 0) {
		fatal("nng_req0_open", rv);
	}
	if ((rv = nng_dialer_create(&dialer, sock, url)) != 0) {
		fatal("nng_dialer_create", rv);
	}
	nng_socket_set_ms(sock, NNG_OPT_REQ_RESENDTIME, 2000);
	nng_dialer_start(dialer, NNG_FLAG_ALLOC);

	if ((rv = nng_send(sock, (void *) cmd, strlen(cmd) + 1, 0)) != 0) {
		fatal("nng_send", rv);
	}

	if ((rv = nng_recv(sock, &buf, &sz, NNG_FLAG_ALLOC)) != 0) {
		fatal("nng_recv", rv);
	}
	if (sz > 0) {
		printf("reload: %.*s\n", (int) sz, (const char *) buf);
	} else {
		printf("no response from broker\n");
	}

	nng_free(buf, sz);
	nng_close(sock);
}

void
start_cmd_client(const char *cmd)
{
	client(cmd);
}
