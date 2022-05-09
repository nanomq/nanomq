//
// Copyright 2021 NanoMQ Team, Inc. <jaylin@emqx.io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "include/client.h"

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <nng/mqtt/mqtt_client.h>
#include <nng/nng.h>
#include <nng/supplemental/util/options.h>
#include <nng/supplemental/util/platform.h>

#if defined(SUPP_CLIENT)

#ifdef NNG_SUPP_TLS
#include <nng/supplemental/tls/tls.h>
static int init_dialer_tls(nng_dialer d, const char *cacert, const char *cert,
    const char *key, const char *pass);
#endif

static void loadfile(const char *path, void **datap, size_t *lenp);
static void fatal(const char *msg, ...);

#define ASSERT_NULL(p, fmt, ...)           \
	if ((p) != NULL) {                 \
		fatal(fmt, ##__VA_ARGS__); \
	}

struct topic {
	struct topic *next;
	char *        val;
};
enum client_type { PUB, SUB, CONN };

struct client_opts {
	enum client_type type;
	bool             verbose;
	size_t           parallel;
	size_t           total_msg_count;
	size_t           interval;
	uint8_t          version;
	char *           url;
	size_t           clients;
	struct topic *   topic;
	size_t           topic_count;
	uint8_t          qos;
	bool             retain;
	char *           user;
	char *           passwd;
	char *           client_id;
	uint16_t         keepalive;
	bool             clean_session;
	uint8_t *        msg;
	size_t           msg_len;
	uint8_t *        will_msg;
	size_t           will_msg_len;
	uint8_t          will_qos;
	bool             will_retain;
	char *           will_topic;
	bool             enable_ssl;
	char *           cacert;
	size_t           cacert_len;
	char *           cert;
	size_t           cert_len;
	char *           key;
	size_t           key_len;
	char *           keypass;
};

typedef struct client_opts client_opts;

client_opts *opts = NULL;

enum options {
	OPT_HELP = 1,
	OPT_VERBOSE,
	OPT_PARALLEL,
	OPT_MSGCOUNT,
	OPT_CLIENTS,
	OPT_INTERVAL,
	OPT_VERSION,
	OPT_URL,
	OPT_PUB,
	OPT_SUB,
	OPT_TOPIC,
	OPT_QOS,
	OPT_RETAIN,
	OPT_USER,
	OPT_PASSWD,
	OPT_CLIENTID,
	OPT_KEEPALIVE,
	OPT_CLEAN_SESSION,
	OPT_WILL_MSG,
	OPT_WILL_QOS,
	OPT_WILL_RETAIN,
	OPT_WILL_TOPIC,
	OPT_SECURE,
	OPT_CACERT,
	OPT_CERTFILE,
	OPT_KEYFILE,
	OPT_KEYPASS,
	OPT_MSG,
	OPT_FILE,
};

static nng_optspec cmd_opts[] = {
	{ .o_name = "help", .o_short = 'h', .o_val = OPT_HELP },
	{ .o_name = "verbose", .o_short = 'v', .o_val = OPT_VERBOSE },
	{ .o_name    = "parallel",
	    .o_short = 'n',
	    .o_val   = OPT_PARALLEL,
	    .o_arg   = true },
	{ .o_name    = "interval",
	    .o_short = 'i',
	    .o_val   = OPT_INTERVAL,
	    .o_arg   = true },
	{ .o_name    = "limit",
	    .o_short = 'L',
	    .o_val   = OPT_MSGCOUNT,
	    .o_arg   = true },
	{ .o_name    = "count",
	    .o_short = 'C',
	    .o_val   = OPT_CLIENTS,
	    .o_arg   = true },
	{ .o_name = "version", .o_short = 'V', .o_val = OPT_VERSION },
	{ .o_name = "url", .o_val = OPT_URL, .o_arg = true },
	{ .o_name    = "topic",
	    .o_short = 't',
	    .o_val   = OPT_TOPIC,
	    .o_arg   = true },
	{ .o_name = "qos", .o_short = 'q', .o_val = OPT_QOS, .o_arg = true },
	{ .o_name = "retain", .o_short = 'r', .o_val = OPT_RETAIN },
	{ .o_name = "user", .o_short = 'u', .o_val = OPT_USER, .o_arg = true },
	{ .o_name    = "password",
	    .o_short = 'p',
	    .o_val   = OPT_PASSWD,
	    .o_arg   = true },
	{ .o_name    = "id",
	    .o_short = 'I',
	    .o_val   = OPT_CLIENTID,
	    .o_arg   = true },
	{ .o_name    = "keepalive",
	    .o_short = 'k',
	    .o_val   = OPT_KEEPALIVE,
	    .o_arg   = true },
	{ .o_name    = "clean_session",
	    .o_short = 'c',
	    .o_val   = OPT_CLEAN_SESSION,
	    .o_arg   = true },
	{ .o_name = "will-msg", .o_val = OPT_WILL_MSG, .o_arg = true },
	{ .o_name = "will-qos", .o_val = OPT_WILL_QOS, .o_arg = true },
	{ .o_name = "will-retain", .o_val = OPT_WILL_RETAIN },
	{ .o_name = "will-topic", .o_val = OPT_WILL_TOPIC, .o_arg = true },
	{ .o_name = "secure", .o_short = 's', .o_val = OPT_SECURE },
	{ .o_name = "cacert", .o_val = OPT_CACERT, .o_arg = true },
	{ .o_name = "key", .o_val = OPT_KEYFILE, .o_arg = true },
	{ .o_name = "keypass", .o_val = OPT_KEYPASS, .o_arg = true },
	{
	    .o_name  = "cert",
	    .o_short = 'E',
	    .o_val   = OPT_CERTFILE,
	    .o_arg   = true,
	},

	{ .o_name = "msg", .o_short = 'm', .o_val = OPT_MSG, .o_arg = true },
	{ .o_name = "file", .o_short = 'f', .o_val = OPT_FILE, .o_arg = true },

	{ .o_name = NULL, .o_val = 0 },
};

struct work {
	enum { INIT, RECV, RECV_WAIT, SEND_WAIT, SEND } state;
	nng_aio *    aio;
	nng_msg *    msg;
	nng_ctx      ctx;
	client_opts *opts;
	size_t       msg_count;
};

static void average_msgs(client_opts *opts, struct work **works);

static void
fatal(const char *msg, ...)
{
	va_list ap;
	va_start(ap, msg);
	vfprintf(stderr, msg, ap);
	va_end(ap);
	fprintf(stderr, "\n");
	exit(1);
}

static void
nng_fatal(const char *msg, int rv)
{
	fatal("%s:%s", msg, nng_strerror(rv));
}

static void
help(enum client_type type)
{
	switch (type) {
	case PUB:
		printf("Usage: nanomq pub { start | stop } <addr> "
		       "[<topic>...] [<opts>...] [<src>]\n\n");
		break;
	case SUB:
		printf("Usage: nanomq sub { start | stop } <addr> "
		       "[<topic>...] [<opts>...]\n\n");
		break;
	case CONN:
		printf("Usage: nanomq conn { start | stop } <addr> "
		       "[<opts>...]\n\n");
		break;

	default:
		break;
	}

	printf("<addr> must be one or more of:\n");
	printf("  --url <url>                      The url for mqtt broker "
	       "('mqtt-tcp://host:port' or 'tls+mqtt-tcp://host:port') \n");
	printf("                                   [default: "
	       "mqtt-tcp://127.0.0.1:1883]\n");

	if (type == PUB || type == SUB) {
		printf("\n<topic> must be set:\n");
		printf(
		    "  -t, --topic <topic>              Topic for publish or "
		    "subscribe\n");
	}

	printf("\n<opts> may be any of:\n");
	printf("  -V, --version <version: 3|4|5>   The MQTT version used by "
	       "the client [default: 4]\n");
	printf("  -n, --parallel             	   The number of parallel for "
	       "client [default: 1]\n");
	printf("  -v, --verbose              	   Enable verbose mode\n");
	printf("  -u, --user <user>                The username for "
	       "authentication\n");
	printf("  -p, --password <password>        The password for "
	       "authentication\n");
	printf("  -k, --keepalive <keepalive>      A keep alive of the client "
	       "(in seconds) [default: 60]\n");
	if (type == PUB) {
		printf("  -m, --msg <message>              The message to "
		       "publish\n");
		printf("  -L, --limit <num>                Max count of "
		       "publishing "
		       "message [default: 1]\n");
		printf("  -i, --interval <ms>              Interval of "
		       "publishing "
		       "message (ms) [default: 10]\n");
		printf(
		    "  -I, --identifier <identifier>    The client identifier "
		    "UTF-8 String (default randomly generated string)\n");
	} else {
		printf("  -i, --interval <ms>              Interval of "
		       "establishing connection "
		       "(ms) [default: 10]\n");
	}
	printf("  -C, --count <num>                Num of client \n");
	printf("  -q, --qos <qos>                  Quality of service for the "
	       "corresponding topic [default: 0]\n");
	printf("  -r, --retain                     The message will be "
	       "retained [default: false]\n");
	printf("  -c, --clean_session <true|false> Define a clean start for "
	       "the connection [default: true]\n");
	printf("  --will-qos <qos>                 Quality of service level "
	       "for the will message [default: 0]\n");
	printf("  --will-msg <message>             The payload of the will "
	       "message\n");
	printf("  --will-topic <topic>             The topic of the will "
	       "message\n");
	printf("  --will-retain                    Will message as retained "
	       "message [default: false]\n");

	printf("  -s, --secure                     Enable TLS/SSL mode\n");
	printf(
	    "      --cacert <file>              CA certificates file path\n");
	printf("      -E, --cert <file>            Certificate file path\n");
	printf("      --key <file>                 Private key file path\n");
	printf("      --keypass <key password>     Private key password\n");

	if (type == PUB) {
		printf("\n<src> may be one of:\n");
		printf("  -m, --msg  <data>                \n");
		printf("  -f, --file <file>                \n");
	}
}

static int
intarg(const char *val, int maxv)
{
	int v = 0;

	if (val[0] == '\0') {
		fatal("Empty integer argument.");
	}
	while (*val != '\0') {
		if (!isdigit(*val)) {
			fatal("Integer argument expected.");
		}
		v *= 10;
		v += ((*val) - '0');
		val++;
		if (v > maxv) {
			fatal("Integer argument too large.");
		}
	}
	if (v < 0) {
		fatal("Integer argument overflow.");
	}
	return (v);
}

struct topic **
addtopic(struct topic **endp, const char *s)
{
	struct topic *t;

	if (((t = malloc(sizeof(*t))) == NULL) ||
	    ((t->val = malloc(strlen(s) + 1)) == NULL)) {
		fatal("Out of memory.");
	}
	memcpy(t->val, s, strlen(s) + 1);
	t->next = NULL;
	*endp   = t;
	return (&t->next);
}

void
freetopic(struct topic *endp)
{
	struct topic *t = endp;

	for (struct topic *t = endp; t != NULL; t = t->next) {
		if (t->val) {
			free(t->val);
			t->val = NULL;
		}
	}
	free(t);
}

int
client_parse_opts(int argc, char **argv, client_opts *opts)
{
	int    idx = 0;
	char * arg;
	int    val;
	int    rv;
	size_t filelen = 0;

	struct topic **topicend;
	topicend = &opts->topic;

	while ((rv = nng_opts_parse(argc, argv, cmd_opts, &val, &arg, &idx)) ==
	    0) {
		switch (val) {
		case OPT_HELP:
			help(opts->type);
			exit(0);
			break;
		case OPT_VERBOSE:
			opts->verbose = true;
			break;
		case OPT_PARALLEL:
			opts->parallel = intarg(arg, 1024000);
			break;
		case OPT_INTERVAL:
			opts->interval = intarg(arg, 10240000);
			break;
		case OPT_MSGCOUNT:
			opts->total_msg_count = intarg(arg, 10240000);
			break;
		case OPT_CLIENTS:
			opts->clients = intarg(arg, 10240000);
			break;
		case OPT_VERSION:
			opts->version = intarg(arg, 4);
			break;
		case OPT_URL:
			ASSERT_NULL(opts->url,
			    "URL (--url) may be specified "
			    "only once.");
			opts->url = nng_strdup(arg);
			break;
		case OPT_TOPIC:
			topicend = addtopic(topicend, arg);
			opts->topic_count++;
			break;
		case OPT_QOS:
			opts->qos = intarg(arg, 2);
			break;
		case OPT_RETAIN:
			opts->retain = true;
			break;
		case OPT_USER:
			ASSERT_NULL(opts->user,
			    "User (-u, --user) may be specified "
			    "only "
			    "once.");
			opts->user = nng_strdup(arg);
			break;
		case OPT_PASSWD:
			ASSERT_NULL(opts->passwd,
			    "Password (-p, --password) may be "
			    "specified "
			    "only "
			    "once.");
			opts->passwd = nng_strdup(arg);
			break;
		case OPT_CLIENTID:
			ASSERT_NULL(opts->client_id,
			    "Identifier (-I, --identifier) may be "
			    "specified "
			    "only "
			    "once.");
			opts->client_id = nng_strdup(arg);
			break;
		case OPT_KEEPALIVE:
			opts->keepalive = intarg(arg, 65535);
			break;
		case OPT_CLEAN_SESSION:
			opts->clean_session = strcasecmp(arg, "true") == 0;
			break;
		case OPT_WILL_MSG:
			ASSERT_NULL(opts->will_msg,
			    "Will_msg (--will-msg) may be specified "
			    "only "
			    "once.");
			opts->will_msg     = nng_strdup(arg);
			opts->will_msg_len = strlen(arg);
			break;
		case OPT_WILL_QOS:
			opts->will_qos = intarg(arg, 2);
			break;
		case OPT_WILL_RETAIN:
			opts->retain = true;
			break;
		case OPT_WILL_TOPIC:
			ASSERT_NULL(opts->will_topic,
			    "Will_topic (--will-topic) may be "
			    "specified "
			    "only "
			    "once.");
			opts->will_topic = nng_strdup(arg);
			break;
		case OPT_SECURE:
			opts->enable_ssl = true;
			break;
		case OPT_CACERT:
			ASSERT_NULL(opts->cacert,
			    "CA Certificate (--cacert) may be "
			    "specified only once.");
			loadfile(
			    arg, (void **) &opts->cacert, &opts->cacert_len);
			break;
		case OPT_CERTFILE:
			ASSERT_NULL(opts->cert,
			    "Cert (--cert) may be specified "
			    "only "
			    "once.");
			loadfile(arg, (void **) &opts->cert, &opts->cert_len);
			break;
		case OPT_KEYFILE:
			ASSERT_NULL(opts->key,
			    "Key (--key) may be specified only once.");
			loadfile(arg, (void **) &opts->key, &opts->key_len);
			break;
		case OPT_KEYPASS:
			ASSERT_NULL(opts->keypass,
			    "Key Password (--keypass) may be specified only "
			    "once.");
			opts->keypass = nng_strdup(arg);
			break;
		case OPT_MSG:
			ASSERT_NULL(opts->msg,
			    "Data (--file, --data) may be "
			    "specified "
			    "only once.");
			opts->msg     = nng_strdup(arg);
			opts->msg_len = strlen(arg);
			break;
		case OPT_FILE:
			ASSERT_NULL(opts->msg,
			    "Data (--file, --data) may be "
			    "specified "
			    "only once.");
			loadfile(arg, (void **) &opts->msg, &opts->msg_len);
			break;
		}
	}
	switch (rv) {
	case NNG_EINVAL:
		fatal("Option %s is invalid.", argv[idx]);
		break;
	case NNG_EAMBIGUOUS:
		fatal("Option %s is ambiguous (specify in full).", argv[idx]);
		break;
	case NNG_ENOARG:
		fatal("Option %s requires argument.", argv[idx]);
		break;
	default:
		break;
	}

	if (!opts->url) {
		opts->url = nng_strdup("mqtt-tcp://127.0.0.1:1883");
	}

	switch (opts->type) {
	case PUB:
		if (opts->topic_count == 0) {
			fatal("Missing required option: '(-t, --topic) "
			      "<topic>'\nTry 'nanomq pub --help' for more "
			      "information. ");
		}

		if (opts->msg == NULL) {
			fatal("Missing required option: '(-m, --msg) "
			      "<message>' or '(-f, --file) <file>'\nTry "
			      "'nanomq pub --help' for more information. ");
		}
		break;
	case SUB:
		if (opts->topic_count == 0) {
			fatal("Missing required option: '(-t, --topic) "
			      "<topic>'\nTry 'nanomq sub --help' for more "
			      "information. ");
		}
		/* code */
		break;
	case CONN:
		/* code */
		break;

	default:
		break;
	}

	return rv;
}

static void
set_default_conf(client_opts *opts)
{
	opts->total_msg_count = 1;
	opts->interval        = 10;
	opts->qos             = 0;
	opts->retain          = false;
	opts->parallel        = 1;
	opts->version         = 4;
	opts->keepalive       = 60;
	opts->clean_session   = true;
	opts->enable_ssl      = false;
	opts->verbose         = false;
	opts->topic_count     = 0;
	opts->clients         = 1;
}

// This reads a file into memory.  Care is taken to ensure that
// the buffer is one byte larger and contains a terminating
// NUL. (Useful for key files and such.)
static void
loadfile(const char *path, void **datap, size_t *lenp)
{
	FILE * f;
	size_t total_read      = 0;
	size_t allocation_size = BUFSIZ;
	char * fdata;
	char * realloc_result;

	if (strcmp(path, "-") == 0) {
		f = stdin;
	} else {
		if ((f = fopen(path, "rb")) == NULL) {
			fatal(
			    "Cannot open file %s: %s", path, strerror(errno));
		}
	}

	if ((fdata = malloc(allocation_size + 1)) == NULL) {
		fatal("Out of memory.");
	}

	while (1) {
		total_read += fread(
		    fdata + total_read, 1, allocation_size - total_read, f);
		if (ferror(f)) {
			if (errno == EINTR) {
				continue;
			}
			fatal(
			    "Read from %s failed: %s", path, strerror(errno));
		}
		if (feof(f)) {
			break;
		}
		if (total_read == allocation_size) {
			if (allocation_size > SIZE_MAX / 2) {
				fatal("Out of memory.");
			}
			allocation_size *= 2;
			if ((realloc_result = realloc(
			         fdata, allocation_size + 1)) == NULL) {
				free(fdata);
				fatal("Out of memory.");
			}
			fdata = realloc_result;
		}
	}
	if (f != stdin) {
		fclose(f);
	}
	fdata[total_read] = '\0';
	*datap            = fdata;
	*lenp             = total_read;
}

#ifdef NNG_SUPP_TLS
static int
init_dialer_tls(nng_dialer d, const char *cacert, const char *cert,
    const char *key, const char *pass)
{
	nng_tls_config *cfg;
	int             rv;

	if ((rv = nng_tls_config_alloc(&cfg, NNG_TLS_MODE_CLIENT)) != 0) {
		return (rv);
	}

	if (cert != NULL && key != NULL) {
		nng_tls_config_auth_mode(cfg, NNG_TLS_AUTH_MODE_REQUIRED);
		if ((rv = nng_tls_config_own_cert(cfg, cert, key, pass)) !=
		    0) {
			goto out;
		}
	} else {
		nng_tls_config_auth_mode(cfg, NNG_TLS_AUTH_MODE_NONE);
	}

	if (cacert != NULL) {
		if ((rv = nng_tls_config_ca_chain(cfg, cacert, NULL)) != 0) {
			goto out;
		}
	}

	rv = nng_dialer_set_ptr(d, NNG_OPT_TLS_CONFIG, cfg);

out:
	nng_tls_config_free(cfg);
	return (rv);
}

#endif

nng_msg *
publish_msg(client_opts *opts)
{
	// create a PUBLISH message
	nng_msg *pubmsg;
	nng_mqtt_msg_alloc(&pubmsg, 0);
	nng_mqtt_msg_set_packet_type(pubmsg, NNG_MQTT_PUBLISH);
	nng_mqtt_msg_set_publish_qos(pubmsg, opts->qos);
	nng_mqtt_msg_set_publish_retain(pubmsg, opts->retain);
	nng_mqtt_msg_set_publish_payload(pubmsg, opts->msg, opts->msg_len);
	nng_mqtt_msg_set_publish_topic(pubmsg, opts->topic->val);
	return pubmsg;
}

void
client_cb(void *arg)
{
	struct work *work = arg;
	nng_msg *    msg  = NULL;
	int          rv;

	switch (work->state) {
	case INIT:
		switch (work->opts->type) {
		case PUB:
			work->msg = publish_msg(work->opts);
			nng_msg_dup(&msg, work->msg);
			nng_aio_set_msg(work->aio, msg);
			msg         = NULL;
			work->state = SEND;
			nng_ctx_send(work->ctx, work->aio);
			break;
		case SUB:
		case CONN:
			work->state = RECV;
			nng_ctx_recv(work->ctx, work->aio);
			break;
		}
		break;

	case RECV:
		if ((rv = nng_aio_result(work->aio)) != 0) {
			nng_fatal("nng_recv_aio", rv);
			work->state = RECV;
			nng_ctx_recv(work->ctx, work->aio);
			break;
		}
		work->msg   = nng_aio_get_msg(work->aio);
		work->state = RECV_WAIT;
		nng_sleep_aio(0, work->aio);
		break;

	case RECV_WAIT:
		msg = work->msg;
		uint32_t payload_len;
		uint8_t *payload =
		    nng_mqtt_msg_get_publish_payload(msg, &payload_len);
		uint32_t    topic_len;
		const char *recv_topic =
		    nng_mqtt_msg_get_publish_topic(msg, &topic_len);

		printf("%.*s: %.*s\n", topic_len, recv_topic, payload_len,
		    (char *) payload);

		nng_msg_header_clear(work->msg);
		nng_msg_clear(work->msg);

		work->state = RECV;
		nng_ctx_recv(work->ctx, work->aio);
		break;

	case SEND:
		if ((rv = nng_aio_result(work->aio)) != 0) {
			nng_msg_free(work->msg);
			nng_fatal("nng_send_aio", rv);
		}
		work->msg_count--;
		if (work->msg_count > 0) {
			nng_msg_dup(&msg, work->msg);
			nng_aio_set_msg(work->aio, msg);
			msg         = NULL;
			work->state = SEND_WAIT;
			nng_sleep_aio(work->opts->interval, work->aio);
		}
		break;

	case SEND_WAIT:
		work->state = SEND;
		nng_ctx_send(work->ctx, work->aio);
		break;

	default:
		nng_fatal("bad state!", NNG_ESTATE);
		break;
	}
	return;
}

static struct work *
alloc_work(nng_socket sock, client_opts *opts)
{
	struct work *w;
	int          rv;

	if ((w = nng_alloc(sizeof(*w))) == NULL) {
		nng_fatal("nng_alloc", NNG_ENOMEM);
	}
	if ((rv = nng_aio_alloc(&w->aio, client_cb, w)) != 0) {
		nng_fatal("nng_aio_alloc", rv);
	}
	if ((rv = nng_ctx_open(&w->ctx, sock)) != 0) {
		nng_fatal("nng_ctx_open", rv);
	}
	w->opts  = opts;
	w->state = INIT;
	return (w);
}

static nng_msg *
connect_msg(client_opts *opts)
{
	nng_msg *msg;
	nng_mqtt_msg_alloc(&msg, 0);
	nng_mqtt_msg_set_packet_type(msg, NNG_MQTT_CONNECT);
	nng_mqtt_msg_set_connect_proto_version(msg, opts->version);
	nng_mqtt_msg_set_connect_keep_alive(msg, opts->keepalive);
	nng_mqtt_msg_set_connect_clean_session(msg, opts->clean_session);

	if (opts->client_id) {
		nng_mqtt_msg_set_connect_client_id(msg, opts->client_id);
	}
	if (opts->user) {
		nng_mqtt_msg_set_connect_user_name(msg, opts->user);
	}
	if (opts->passwd) {
		nng_mqtt_msg_set_connect_password(msg, opts->passwd);
	}
	if (opts->will_topic) {
		nng_mqtt_msg_set_connect_will_topic(msg, opts->will_topic);
	}
	if (opts->will_qos) {
		nng_mqtt_msg_set_connect_will_qos(msg, opts->will_qos);
	}
	if (opts->will_msg) {
		nng_mqtt_msg_set_connect_will_msg(
		    msg, opts->will_msg, opts->will_msg_len);
	}
	if (opts->will_retain) {
		nng_mqtt_msg_set_connect_will_retain(msg, opts->will_retain);
	}

	return msg;
}

struct connect_param {
	nng_socket * sock;
	client_opts *opts;
	size_t       id;
};

static void
connect_cb(nng_pipe p, nng_pipe_ev ev, void *arg)
{
	struct connect_param *param = arg;
	printf("%s: %s connected!\n", __FUNCTION__, param->opts->url);
}

// Disconnect message callback function
static void
disconnect_cb(nng_pipe p, nng_pipe_ev ev, void *arg)
{
	printf("disconnected\n");
}

static void
create_client(nng_socket *sock, struct work **works, size_t id, size_t nwork,
    struct connect_param *param)
{
	int        rv;
	nng_dialer dialer;

	if ((rv = nng_mqtt_client_open(sock)) != 0) {
		nng_fatal("nng_socket", rv);
	}

	for (size_t i = 0; i < opts->parallel; i++) {
		works[i] = alloc_work(*sock, opts);
	}

	nng_msg *msg = connect_msg(opts);

	if ((rv = nng_dialer_create(&dialer, *sock, opts->url)) != 0) {
		nng_fatal("nng_dialer_create", rv);
	}

#ifdef NNG_SUPP_TLS
	if (opts->enable_ssl) {
		if ((rv = init_dialer_tls(dialer, opts->cacert, opts->cert,
		         opts->key, opts->keypass)) != 0) {
			fatal("init_dialer_tls", rv);
		}
	}
#endif

	nng_dialer_set_ptr(dialer, NNG_OPT_MQTT_CONNMSG, msg);

	param->sock = sock;
	param->opts = opts;
	param->id   = id;

	nng_mqtt_set_connect_cb(*sock, connect_cb, param);
	nng_mqtt_set_disconnect_cb(*sock, disconnect_cb, msg);

	nng_dialer_start(dialer, NNG_FLAG_NONBLOCK);

	if (param->opts->type == SUB && param->opts->topic_count > 0) {
		nng_msg *msg;
		nng_mqtt_msg_alloc(&msg, 0);
		nng_mqtt_msg_set_packet_type(msg, NNG_MQTT_SUBSCRIBE);

		nng_mqtt_topic_qos *topics_qos =
		    nng_mqtt_topic_qos_array_create(param->opts->topic_count);

		size_t i = 0;
		for (struct topic *tp = param->opts->topic;
		     tp != NULL && i < param->opts->topic_count;
		     tp = tp->next, i++) {
			nng_mqtt_topic_qos_array_set(
			    topics_qos, i, tp->val, param->opts->qos);
		}

		nng_mqtt_msg_set_subscribe_topics(
		    msg, topics_qos, param->opts->topic_count);

		nng_mqtt_topic_qos_array_free(
		    topics_qos, param->opts->topic_count);

		// Send subscribe message
		nng_sendmsg(*param->sock, msg, NNG_FLAG_NONBLOCK);
	}

	average_msgs(opts, works);
	for (size_t i = 0; i < opts->parallel; i++) {
		client_cb(works[i]);
	}
}

static void
average_msgs(client_opts *opts, struct work **works)
{
	size_t total_msgs   = opts->total_msg_count;
	size_t remainder    = total_msgs % opts->parallel;
	size_t average_msgs = total_msgs / opts->parallel;
	for (size_t i = 0; i < opts->parallel; i++) {
		works[i]->msg_count = average_msgs;
	}
	if (remainder > 0) {
		for (size_t i = 0; i < remainder; i++) {
			works[i]->msg_count += 1;
		}
	}
}

static void
client(int argc, char **argv, enum client_type type)
{
	int rv;
	opts = nng_zalloc(sizeof(client_opts));
	set_default_conf(opts);
	opts->type = type;

	client_parse_opts(argc, argv, opts);

	if (opts->interval == 0 && opts->total_msg_count > 0) {
		opts->interval = 1;
	}
	if (opts->total_msg_count < opts->parallel) {
		opts->parallel = opts->total_msg_count;
	}

	struct connect_param **param =
	    nng_zalloc(sizeof(struct connect_param *) * opts->clients);
	nng_socket **socket = nng_zalloc(sizeof(nng_socket *) * opts->clients);

	struct work ***works =
	    nng_zalloc(sizeof(struct work **) * opts->clients);

	for (size_t i = 0; i < opts->clients; i++) {
		param[i]  = nng_zalloc(sizeof(struct connect_param));
		socket[i] = nng_zalloc(sizeof(nng_socket));
		works[i] = nng_zalloc(sizeof(struct work **) * opts->parallel);
		create_client(
		    socket[i], works[i], i, opts->parallel, param[i]);
		nng_msleep(opts->interval);
	}

	for (;;) {
		nng_msleep(1000);
	}

	for (size_t j = 0; j < opts->clients; j++) {
		nng_free(param[j], sizeof(struct connect_param));
		nng_free(socket[j], sizeof(nng_socket));

		for (size_t k = 0; k < opts->parallel; k++) {
			nng_aio_free(works[j][k]->aio);
			if (works[j][k]->msg) {
				nng_msg_free(works[j][k]->msg);
				works[j][k]->msg = NULL;
			}

			nng_free(works[j][k], sizeof(struct work));
		}
		nng_free(works[j], sizeof(struct work *));
	}

	nng_free(param, sizeof(struct connect_param **));
	nng_free(socket, sizeof(nng_socket **));
	nng_free(works, sizeof(struct work ***));

	client_stop(argc, argv);
}

int
pub_start(int argc, char **argv)
{
	client(argc, argv, PUB);
	return 0;
}

int
sub_start(int argc, char **argv)
{
	client(argc, argv, SUB);
	return 0;
}

int
conn_start(int argc, char **argv)
{
	client(argc, argv, CONN);
	return 0;
}

int
pub_dflt(int argc, char **argv)
{
	help(PUB);
	return 0;
}

int
sub_dflt(int argc, char **argv)
{
	help(SUB);
	return 0;
}

int
conn_dflt(int argc, char **argv)
{
	help(CONN);
	return 0;
}

int
client_stop(int argc, char **argv)
{
	if (opts) {
		if (opts->url) {
			nng_strfree(opts->url);
		}
		if (opts->topic) {
			freetopic(opts->topic);
		}
		if (opts->user) {
			nng_strfree(opts->user);
		}
		if (opts->passwd) {
			nng_strfree(opts->passwd);
		}
		if (opts->client_id) {
			nng_strfree(opts->client_id);
		}
		if (opts->msg) {
			nng_free(opts->msg, opts->msg_len);
		}
		if (opts->will_msg) {
			nng_free(opts->will_msg, opts->will_msg_len);
		}
		if (opts->will_topic) {
			nng_strfree(opts->will_topic);
		}
		if (opts->cacert) {
			nng_free(opts->cacert, opts->cacert_len);
		}
		if (opts->cert) {
			nng_free(opts->cert, opts->cert_len);
		}
		if (opts->key) {
			nng_free(opts->key, opts->key_len);
		}
		if (opts->keypass) {
			nng_strfree(opts->keypass);
		}

		free(opts);
	}

	return 0;
}

#endif
