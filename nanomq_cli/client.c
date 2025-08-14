//
// Copyright 2024 NanoMQ Team, Inc. <jaylin@emqx.io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "client.h"

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nng/mqtt/mqtt_client.h"
#include "nng/nng.h"
#include "nng/protocol/mqtt/mqtt_parser.h"
#include "nng/supplemental/util/options.h"
#include "nng/supplemental/util/platform.h"
#include "nng/supplemental/nanolib/utils.h"
#include "nng/supplemental/nanolib/file.h"


#if defined(SUPP_CLIENT)

#ifdef NNG_SUPP_TLS
#include <nng/supplemental/tls/tls.h>
static int init_dialer_tls(nng_dialer d, const char *cacert, const char *cert,
    const char *key, const char *pass);
#endif

static nng_msg *conn_msg;
static void loadfile(const char *path, void **datap, size_t *lenp);

#define ASSERT_NULL(p, fmt, ...)           \
	if ((p) != NULL) {                 \
		fatal(fmt, ##__VA_ARGS__); \
	}

struct topic {
	struct topic *next;
	char *        val;
};

enum client_type { PUB = 1, SUB = 1 << 1, CONN = 1 << 2 };

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
	bool             stdin_line;
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
	property *       conn_properties;
	property *       sub_properties;
	property *       pub_properties;
};

typedef struct client_opts client_opts;

struct connect_param {
	nng_socket *     sock;
	nng_mqtt_client *client;
	client_opts *    opts;
	size_t           id;
};

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
	OPT_HOST,
	OPT_PORT,
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
	OPT_QUIC,
	OPT_SECURE,
	OPT_CACERT,
	OPT_CERTFILE,
	OPT_KEYFILE,
	OPT_KEYPASS,
	OPT_MSG,
	OPT_FILE,
	OPT_STDIN_LINE,
	// property options >>>>>>>>>>>>>
	OPT_PAYLOAD_FORMAT_INDICATOR,
	OPT_MESSAGE_EXPIRY_INTERVAL,
	OPT_CONTENT_TYPE,
	OPT_RESPONSE_TOPIC,
	OPT_CORRELATION_DATA,
	OPT_SESSION_EXPIRY_INTERVAL,
	OPT_ASSIGNED_CLIENT_IDENTIFIER,
	OPT_SERVER_KEEP_ALIVE,
	OPT_AUTHENTICATION_METHOD,
	OPT_AUTHENTICATION_DATA,
	OPT_REQUEST_PROBLEM_INFORMATION,
	OPT_WILL_DELAY_INTERVAL,
	OPT_REQUEST_RESPONSE_INFORMATION,
	OPT_RESPONSE_INFORMATION,
	OPT_SERVER_REFERENCE,
	OPT_REASON_STRING,
	OPT_RECEIVE_MAXIMUM,
	OPT_TOPIC_ALIAS_MAXIMUM,
	OPT_TOPIC_ALIAS,
	OPT_PUBLISH_MAXIMUM_QOS,
	OPT_RETAIN_AVAILABLE,
	OPT_USER_PROPERTY,
	OPT_MAXIMUM_PACKET_SIZE,
	OPT_WILDCARD_SUBSCRIPTION_AVAILABLE,
	OPT_SUBSCRIPTION_IDENTIFIER_AVAILABLE,
	OPT_SHARED_SUBSCRIPTION_AVAILABLE,
	// property options <<<<<<<<<<<<<<
	OPT_UNKNOWN,
};

static nng_optspec cmd_opts[] = {
	{ .o_name = "help", .o_val = OPT_HELP },
	{ .o_name = "verbose", .o_short = 'v', .o_val = OPT_VERBOSE },
	{ .o_name    = "parallel",
	    .o_short = 'n',
	    .o_val   = OPT_PARALLEL,
	    .o_arg   = true },
	{ .o_name    = "interval",
	    .o_short = 'I',
	    .o_val   = OPT_INTERVAL,
	    .o_arg   = true },
	{ .o_name    = "limit",
	    .o_short = 'L',
	    .o_val   = OPT_MSGCOUNT,
	    .o_arg   = true },
	{ .o_name    = "host",
	    .o_short = 'h',
	    .o_val   = OPT_HOST,
	    .o_arg   = true },
	{ .o_name    = "port",
	    .o_short = 'p',
	    .o_val   = OPT_PORT,
	    .o_arg   = true },
	{ .o_name    = "count",
	    .o_short = 'C',
	    .o_val   = OPT_CLIENTS,
	    .o_arg   = true },
	{ .o_name    = "version",
	    .o_short = 'V',
	    .o_val   = OPT_VERSION,
	    .o_arg   = true },
	{ .o_name = "url", .o_val = OPT_URL, .o_arg = true },
	{ .o_name    = "topic",
	    .o_short = 't',
	    .o_val   = OPT_TOPIC,
	    .o_arg   = true },
	{ .o_name = "qos", .o_short = 'q', .o_val = OPT_QOS, .o_arg = true },
	{ .o_name = "retain", .o_short = 'r', .o_val = OPT_RETAIN },
	{ .o_name = "user", .o_short = 'u', .o_val = OPT_USER, .o_arg = true },
	{ .o_name    = "password",
	    .o_short = 'P',
	    .o_val   = OPT_PASSWD,
	    .o_arg   = true },
	{ .o_name    = "id",
	    .o_short = 'i',
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
	{ .o_name = "quic", .o_val = OPT_QUIC },
	{ .o_name = "cafile", .o_val = OPT_CACERT, .o_arg = true },
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
	{ .o_name = "stdin-line", .o_short = 'l', .o_val = OPT_STDIN_LINE },
	{ .o_name  = "payload_format_indicator",
	    .o_val = OPT_PAYLOAD_FORMAT_INDICATOR,
	    .o_arg = true },
	{ .o_name  = "message_expiry_interval",
	    .o_val = OPT_MESSAGE_EXPIRY_INTERVAL,
	    .o_arg = true },
	{ .o_name = "content_type", .o_val = OPT_CONTENT_TYPE, .o_arg = true },
	{ .o_name  = "response_topic",
	    .o_val = OPT_RESPONSE_TOPIC,
	    .o_arg = true },
	{ .o_name  = "correlation_data",
	    .o_val = OPT_CORRELATION_DATA,
	    .o_arg = true },
	{ .o_name  = "session_expiry_interval",
	    .o_val = OPT_SESSION_EXPIRY_INTERVAL,
	    .o_arg = true },
	{ .o_name  = "assigned_client_identifier",
	    .o_val = OPT_ASSIGNED_CLIENT_IDENTIFIER,
	    .o_arg = true },
	{ .o_name  = "server_keep_alive",
	    .o_val = OPT_SERVER_KEEP_ALIVE,
	    .o_arg = true },
	// { .o_name  = "authentication_method",
	//     .o_val = OPT_AUTHENTICATION_METHOD,
	//     .o_arg = true },
	// { .o_name  = "authentication_data",
	//     .o_val = OPT_AUTHENTICATION_DATA,
	    // .o_arg = true },
	{ .o_name  = "request_problem_information",
	    .o_val = OPT_REQUEST_PROBLEM_INFORMATION,
	    .o_arg = true },
	{ .o_name  = "will_delay_interval",
	    .o_val = OPT_WILL_DELAY_INTERVAL,
	    .o_arg = true },
	{ .o_name  = "request_response_information",
	    .o_val = OPT_REQUEST_RESPONSE_INFORMATION,
	    .o_arg = true },
	{ .o_name  = "response_information",
	    .o_val = OPT_RESPONSE_INFORMATION,
	    .o_arg = true },
	{ .o_name  = "server_reference",
	    .o_val = OPT_SERVER_REFERENCE,
	    .o_arg = true },
	{ .o_name  = "reason_string",
	    .o_val = OPT_REASON_STRING,
	    .o_arg = true },
	{ .o_name  = "receive_maximum",
	    .o_val = OPT_RECEIVE_MAXIMUM,
	    .o_arg = true },
	{ .o_name  = "topic_alias_maximum",
	    .o_val = OPT_TOPIC_ALIAS_MAXIMUM,
	    .o_arg = true },
	{ .o_name = "topic_alias", .o_val = OPT_TOPIC_ALIAS, .o_arg = true },
	{ .o_name  = "publish_maximum_qos",
	    .o_val = OPT_PUBLISH_MAXIMUM_QOS,
	    .o_arg = true },
	{ .o_name  = "retain_available",
	    .o_val = OPT_RETAIN_AVAILABLE,
	    .o_arg = true },
	{ .o_name  = "user_property",
	    .o_val = OPT_USER_PROPERTY,
	    .o_arg = true },
	{ .o_name  = "maximum_packet_size",
	    .o_val = OPT_MAXIMUM_PACKET_SIZE,
	    .o_arg = true },
	{ .o_name  = "wildcard_subscription_available",
	    .o_val = OPT_WILDCARD_SUBSCRIPTION_AVAILABLE,
	    .o_arg = true },
	{ .o_name  = "subscription_identifier_available",
	    .o_val = OPT_SUBSCRIPTION_IDENTIFIER_AVAILABLE,
	    .o_arg = true },
	{ .o_name  = "shared_subscription_available",
	    .o_val = OPT_SHARED_SUBSCRIPTION_AVAILABLE,
	    .o_arg = true },
	{ .o_name = NULL, .o_val = 0 },
};

typedef struct {
	uint8_t     type;
	const char *usage;
} arg_usage;

static arg_usage properties_usage[] = {
	{
	    .type  = (PUB | SUB | CONN),
	    .usage = "payload_format_indicator       The payload format "
	             "indicator of the publish message",
	},
	{
	    .type  = (PUB | SUB | CONN),
	    .usage = "message_expiry_interval        The lifetime of the "
	             "publish message in seconds (default: no message expiry)",
	},
	{
	    .type  = (PUB | SUB | CONN),
	    .usage = "content_type                   A description of publish "
	             "message's content",
	},
	{
	    .type  = (PUB | SUB | CONN),
	    .usage = "response_topic                 The topic name for the "
	             "publish message`s response message",
	},
	{
	    .type  = (PUB | SUB | CONN),
	    .usage = "correlation_data               The correlation data of "
	             "the publish message",
	},
	{
	    .type  = (PUB | SUB | CONN),
	    .usage = "session_expiry_interval        The lifetime of the "
	             "session of the connected client",
	},
	// {
	//     .type  = (CONN),
	//     .usage = "authentication_method",
	// },
	// {
	//     .type  = (CONN),
	//     .usage = "authentication_data",
	// },
	{
	    .type  = (PUB | SUB | CONN),
	    .usage = "request_problem_information    The client requests "
	             "problem information from the server. (default: true)",
	},
	{
	    .type  = (PUB | SUB | CONN),
	    .usage = "will_delay_interval            The Server delays "
	             "publishing the client's will message until the will "
	             "delay has passed (default: 0)",
	},
	{
	    .type  = (PUB | SUB | CONN),
	    .usage = "request_response_information   The client requests "
	             "response information from the server. (default: false)",
	},
	{
	    .type  = (PUB | SUB | CONN),
	    .usage = "receive_maximum                The maximum amount of "
	             "not acknowledged publishes with QoS 1 or 2 the client "
	             "accepts from the server concurrently. (default: 65535)",
	},
	{
	    .type = (PUB | SUB | CONN),
	    .usage =
	        "topic_alias_maximum            The maximum amount of topic "
	        "aliases the client accepts from the server. (default: 0)",
	},
	{
	    .type  = (PUB),
	    .usage = "topic_alias                    The "
	             "topic alias of the publish message",
	},
	{
	    .type  = (PUB | SUB | CONN),
	    .usage = "user_property                  User property ",
	},
	{
	    .type  = (PUB | SUB | CONN),
	    .usage = "maximum_packet_size            The maximum packet size "
	             "the client accepts from the server.",
	},
};

struct work {
	enum { INIT, RECV, RECV_WAIT, SEND_WAIT, SEND } state;
	nng_aio *    aio;
	nng_msg *    msg;
	nng_ctx      ctx;
	client_opts *opts;
	size_t       msg_count;
	nng_socket  *sock;
};

#if defined(SUPP_QUIC)
#include <nng/mqtt/mqtt_quic_client.h>
#endif

static void average_msgs(client_opts *opts, struct work **works);
static void free_opts(void);

void
console(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stdout, fmt, ap);
	va_end(ap);
	fflush(stdout);
}

static void
properties_help(enum client_type type)
{
	for (size_t i = 0;
	     i < sizeof(properties_usage) / sizeof(properties_usage[0]); i++) {
		if (0 != (type & properties_usage[i].type)) {
			console("  --%s\n", properties_usage[i].usage);
		}
	}
}

static void
help(enum client_type type)
{
	switch (type) {
	case PUB:
		console("Usage: nanomq_cli pub"
		       "[<topic>...] [<opts>...] [<src>]\n\n");
		break;
	case SUB:
		console("Usage: nanomq_cli sub"
		       "[<topic>...] [<opts>...]\n\n");
		break;
	case CONN:
		console("Usage: nanomq_cli conn"
		       "[<opts>...]\n\n");
		break;

	default:
		break;
	}


	if (type == PUB || type == SUB) {
		console("\n<topic> must be set:\n");
		console(
		    "  -t, --topic <topic>              Topic for publish or "
		    "subscribe\n");
	}

	console("\n<opts> may be any of:\n");
	console("  -h, --host                       Mqtt host to connect to. "
	        "Defaults to localhost.\n");
	console("  -p, --port                       Network port to connect "
	        "to. ( Defaults to 1883\n");
	console("                                   for plain MQTT, 8883 for "
	        "MQTT over TLS, 14567\n");
	console("                                   for MQTT over QUIC.) \n");
	console("  -V, --version <version: 3|4|5>   The MQTT version used by "
	        "the client [default: 4]\n");
	console("  -n, --parallel             	   The number of parallel for "
	        "client [default: 1]\n");
	console("  -v, --verbose              	   Enable verbose mode\n");
	console("  -u, --user <user>                The username for "
	        "authentication\n");
	console("  -P, --password <password>        The password for "
	       "authentication\n");
	console("  -k, --keepalive <keepalive>      A keep alive of the client "
	       "(in seconds) [default: 60]\n");
	if (type == PUB) {
		console("  -m, --msg <message>              The message to "
		       "publish\n");
		console("  -L, --limit <num>                Max count of "
		        "publishing "
		        "message [default: 1]\n");
		console("  -l, --stdin-line                 Send messages "
		        "read from stdin, splitting separate lines into "
		        "separate messages.[default: false]\n");
		console("  -I, --interval <ms>              Interval of "
		        "publishing "
		        "message (ms) [default: 10]\n");
	} else {
		console("  -I, --interval <ms>              Interval of "
		       "establishing connection "
		       "(ms) [default: 10]\n");
	}

	console("  -i, --identifier <identifier>    The client identifier "
	        "UTF-8 String (default randomly generated string)\n");
	console("  -C, --count <num>                Num of client \n");

	console("  -q, --qos <qos>                  Quality of "
	        "service for the "
	        "corresponding topic ");
	if (type == SUB) {
		console("[default: 2]\n");
	} else {
		console("[default: 0]\n");
	}
	console("  -r, --retain                     The message will be "
	        "retained [default: false]\n");
	console("  -c, --clean_session <true|false> Define a clean start for "
	        "the connection [default: true]\n");
	console("  --will-qos <qos>                 Quality of service level "
	        "for the will message [default: 0]\n");
	console("  --will-msg <message>             The payload of the will "
	        "message\n");
	console("  --will-topic <topic>             The topic of the will "
	        "message\n");
	console("  --will-retain                    Will message as retained "
	        "message [default: false]\n");
	console("  --quic                           QUIC transport [default: "
	        "false]\n");

	properties_help(type);

#if defined(NNG_SUPP_TLS)
	console("  -s, --secure                     Enable TLS/SSL mode\n");
	console(
	        "      --cafile <file>              CA certificates file path\n");
	console("      -E, --cert <file>            Certificate file path\n");
	console("      --key <file>                 Private key file path\n");
	console("      --keypass <key password>     Private key password\n");
#endif

	if (type == PUB) {
		console("\n<src> may be one of:\n");
		console("  -m, --msg  <data>                \n");
		console("  -f, --file <file>                \n");
	}
}

static long
long_arg(const char *val, long minv, long maxv)
{
	long v = 0;

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
			fatal(
			    "Integer argument too large (value < %ld).", maxv);
		} else if (v < minv) {
			fatal(
			    "Integer argument too small (value > %ld).", minv);
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

	for (; t != NULL; t = t->next) {
		if (t->val) {
			free(t->val);
			t->val = NULL;
		}
	}
	free(t);
}

int
client_parse_opts(int argc, char **argv, client_opts *opt)
{
	char    *arg;
	int      val;
	int      rv;
	int      idx     = 1;
	char    *proto   = "mqtt-tcp";
	char    *host    = "127.0.0.1";
	char    *port    = NULL;
	size_t   filelen = 0;

	struct topic **topicend;
	topicend = &opt->topic;

	while ((rv = nng_opts_parse(
	            argc - 1, argv + 1, cmd_opts, &val, &arg, &idx)) == 0) {
		switch (val) {
		case OPT_HELP:
			help(opt->type);
			exit(0);
			break;
		case OPT_VERBOSE:
			opt->verbose = true;
			break;
		case OPT_PARALLEL:
			opt->parallel = long_arg(arg, 1, 1024000);
			break;
		case OPT_INTERVAL:
			opt->interval = long_arg(arg, 1, 10240000);
			break;
		case OPT_MSGCOUNT:
			opt->total_msg_count = long_arg(arg, 1, 10240000);
			break;
		case OPT_CLIENTS:
			opt->clients = long_arg(arg, 1, 10240000);
			break;
		case OPT_VERSION:
			opt->version = long_arg(arg, 3, 5);
			break;
		case OPT_URL:
			ASSERT_NULL(opt->url,
			    "URL (--url) may be specified "
			    "only once.");
			opt->url = nng_strdup(arg);
			break;
		case OPT_HOST:
			host = arg;
			break;
		case OPT_PORT:
			port = arg;
			break;
		case OPT_TOPIC:
			topicend = addtopic(topicend, arg);
			opt->topic_count++;
			break;
		case OPT_QOS:
			opt->qos = long_arg(arg, 0, 2);
			break;
		case OPT_RETAIN:
			opt->retain = true;
			break;
		case OPT_USER:
			ASSERT_NULL(opt->user,
			    "User (-u, --user) may be specified "
			    "only once.");
			opt->user = nng_strdup(arg);
			break;
		case OPT_PASSWD:
			ASSERT_NULL(opt->passwd,
			    "Password (-P, --password) may be "
			    "specified only once.");
			opt->passwd = nng_strdup(arg);
			break;
		case OPT_CLIENTID:
			ASSERT_NULL(opt->client_id,
			    "Identifier (-i, --identifier) may be "
			    "specified only once.");
			opt->client_id = nng_strdup(arg);
			break;
		case OPT_KEEPALIVE:
			opt->keepalive = long_arg(arg, 0, 65535);
			break;
		case OPT_CLEAN_SESSION:
			opt->clean_session = nng_strcasecmp(arg, "true") == 0;
			break;
		case OPT_WILL_MSG:
			ASSERT_NULL(opt->will_msg,
			    "Will_msg (--will-msg) may be specified "
			    "only once.");
			opt->will_msg     = (uint8_t *) nng_strdup(arg);
			opt->will_msg_len = strlen(arg);
			break;
		case OPT_WILL_QOS:
			opt->will_qos = long_arg(arg, 0, 2);
			break;
		case OPT_WILL_RETAIN:
			opt->retain = true;
			break;
		case OPT_WILL_TOPIC:
			ASSERT_NULL(opt->will_topic,
			    "Will_topic (--will-topic) may be "
			    "specified only once.");
			opt->will_topic = nng_strdup(arg);
			break;
		case OPT_SECURE:
			opt->enable_ssl = true;
			proto           = "tls+mqtt-tcp";
			port            = port == NULL ? "8883" : port;
			break;
		case OPT_QUIC:
			opt->enable_ssl = true;
			proto           = "mqtt-quic";
			port            = port == NULL ? "14567" : port;
			break;
		case OPT_CACERT:
			ASSERT_NULL(opt->cacert,
			    "CA Certificate (--cafile) may be "
			    "specified only once.");
			loadfile(
			    arg, (void **) &opt->cacert, &opt->cacert_len);
			break;
		case OPT_CERTFILE:
			ASSERT_NULL(opt->cert,
			    "Cert (--cert) may be specified "
			    "only once.");
			loadfile(arg, (void **) &opt->cert, &opt->cert_len);
			break;
		case OPT_KEYFILE:
			ASSERT_NULL(opt->key,
			    "Key (--key) may be specified only once.");
			loadfile(arg, (void **) &opt->key, &opt->key_len);
			break;
		case OPT_KEYPASS:
			ASSERT_NULL(opt->keypass,
			    "Key Password (--keypass) may be specified only "
			    "once.");
			opt->keypass = nng_strdup(arg);
			break;
		case OPT_MSG:
			ASSERT_NULL(opt->msg,
			    "Data (--file, --data) may be "
			    "specified only once.");
			opt->msg     = (uint8_t *) nng_strdup(arg);
			opt->msg_len = strlen(arg);
			break;
		case OPT_FILE:
			ASSERT_NULL(opt->msg,
			    "Data (--file, --data) may be "
			    "specified only once.");
			loadfile(arg, (void **) &opt->msg, &opt->msg_len);
			break;
		case OPT_STDIN_LINE:
			opt->stdin_line = true;
			break;
		}
	}
	switch (rv) {
	case NNG_EINVAL:
		fatal("Option %s is invalid.", argv[idx]);
		help(opt->type);
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


	char addr[128] = { 0 };
	port = port == NULL ? "1883" : port;
	snprintf(addr, 128, "%s://%s:%s", proto, host, port);
	opt->url = nng_strdup(addr);


	switch (opt->type) {
	case PUB:
		if (opt->topic_count == 0) {
			fatal("Missing required option: '(-t, --topic) "
			      "<topic>'\nTry 'nanomq_cli pub --help' for more "
			      "information. ");
		}

		if (opt->msg == NULL && opt->stdin_line == false) {
			fatal(
			    "Missing required option: '(-m, --msg) "
			    "<message>' ,(-l, --stdin-line) or '(-f, --file) <file>'\nTry "
			    "'nanomq_cli pub --help' for more information. ");
		}
		break;
	case SUB:
		if (opt->topic_count == 0) {
			fatal("Missing required option: '(-t, --topic) "
			      "<topic>'\nTry 'nanomq_cli sub --help' for more "
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

static uint8_t
property_id_type(properties_type id)
{
	uint8_t type = 0;
	switch (id) {
	case PAYLOAD_FORMAT_INDICATOR:
	case MESSAGE_EXPIRY_INTERVAL:
	case CONTENT_TYPE:
	case RESPONSE_TOPIC:
	case CORRELATION_DATA:
		type = (PUB | CONN);
		break;
	case SUBSCRIPTION_IDENTIFIER:
		type = (PUB | SUB);
		break;
	case SESSION_EXPIRY_INTERVAL:
	case AUTHENTICATION_METHOD:
	case AUTHENTICATION_DATA:
	case REQUEST_PROBLEM_INFORMATION:
	case WILL_DELAY_INTERVAL:
	case REQUEST_RESPONSE_INFORMATION:
	case RECEIVE_MAXIMUM:
	case TOPIC_ALIAS_MAXIMUM:
		type = CONN;
		break;
	case TOPIC_ALIAS:
		type = PUB;
		break;
	case USER_PROPERTY:
		type = PUB | SUB | CONN;
		break;
	case MAXIMUM_PACKET_SIZE:
		type = CONN;
		break;
	default:
		break;
	}

	return type;
}

static int
properties_classify(property *properties, client_opts *opts)
{
	switch (opts->type) {
	case CONN:
		opts->conn_properties = mqtt_property_alloc();
		break;
	case PUB:
		opts->conn_properties = mqtt_property_alloc();
		opts->pub_properties  = mqtt_property_alloc();
		break;
	case SUB:
		opts->conn_properties = mqtt_property_alloc();
		opts->sub_properties  = mqtt_property_alloc();
		break;
	default:
		break;
	}

	property *item;

	for (property *p = properties->next; p != NULL; p = p->next) {
		uint8_t type = property_id_type(p->id);
		if (type == 0) {
			fatal("Unknown property id: %d", p->id);
		}
		if (CONN == (type & CONN)) {
			item     = mqtt_property_alloc();
			item->id = p->id;
			mqtt_property_value_copy(item, p);
			mqtt_property_append(opts->conn_properties, item);
		}
		if (PUB == (type & PUB)) {
			item     = mqtt_property_alloc();
			item->id = p->id;
			mqtt_property_value_copy(item, p);
			mqtt_property_append(opts->pub_properties, item);
		}
		if (SUB == (type & SUB)) {
			item     = mqtt_property_alloc();
			item->id = p->id;
			mqtt_property_value_copy(item, p);
			mqtt_property_append(opts->sub_properties, item);
		}
	}

	return 0;
}

static properties_type
properties_type_parse(int val)
{
	properties_type prop_id = 0;
	switch (val) {
	case OPT_PAYLOAD_FORMAT_INDICATOR:
		prop_id = PAYLOAD_FORMAT_INDICATOR;
		break;
	case OPT_MESSAGE_EXPIRY_INTERVAL:
		prop_id = MESSAGE_EXPIRY_INTERVAL;
		break;
	case OPT_CONTENT_TYPE:
		prop_id = CONTENT_TYPE;
		break;
	case OPT_RESPONSE_TOPIC:
		prop_id = RESPONSE_TOPIC;
		break;
	case OPT_CORRELATION_DATA:
		prop_id = CORRELATION_DATA;
		break;
	case OPT_SESSION_EXPIRY_INTERVAL:
		prop_id = SESSION_EXPIRY_INTERVAL;
		break;
	case OPT_ASSIGNED_CLIENT_IDENTIFIER:
		prop_id = ASSIGNED_CLIENT_IDENTIFIER;
		break;
	case OPT_SERVER_KEEP_ALIVE:
		prop_id = SERVER_KEEP_ALIVE;
		break;
	case OPT_AUTHENTICATION_METHOD:
		prop_id = AUTHENTICATION_METHOD;
		break;
	case OPT_AUTHENTICATION_DATA:
		prop_id = AUTHENTICATION_DATA;
		break;
	case OPT_REQUEST_PROBLEM_INFORMATION:
		prop_id = REQUEST_PROBLEM_INFORMATION;
		break;
	case OPT_WILL_DELAY_INTERVAL:
		prop_id = WILL_DELAY_INTERVAL;
		break;
	case OPT_REQUEST_RESPONSE_INFORMATION:
		prop_id = REQUEST_RESPONSE_INFORMATION;
		break;
	case OPT_RESPONSE_INFORMATION:
		prop_id = RESPONSE_INFORMATION;
		break;
	case OPT_SERVER_REFERENCE:
		prop_id = SERVER_REFERENCE;
		break;
	case OPT_REASON_STRING:
		prop_id = REASON_STRING;
		break;
	case OPT_RECEIVE_MAXIMUM:
		prop_id = RECEIVE_MAXIMUM;
		break;
	case OPT_TOPIC_ALIAS_MAXIMUM:
		prop_id = TOPIC_ALIAS_MAXIMUM;
		break;
	case OPT_TOPIC_ALIAS:
		prop_id = TOPIC_ALIAS;
		break;
	case OPT_PUBLISH_MAXIMUM_QOS:
		prop_id = PUBLISH_MAXIMUM_QOS;
		break;
	case OPT_RETAIN_AVAILABLE:
		prop_id = RETAIN_AVAILABLE;
		break;
	case OPT_USER_PROPERTY:
		prop_id = USER_PROPERTY;
		break;
	case OPT_MAXIMUM_PACKET_SIZE:
		prop_id = MAXIMUM_PACKET_SIZE;
		break;
	case OPT_WILDCARD_SUBSCRIPTION_AVAILABLE:
		prop_id = WILDCARD_SUBSCRIPTION_AVAILABLE;
		break;
	case OPT_SUBSCRIPTION_IDENTIFIER_AVAILABLE:
		prop_id = SUBSCRIPTION_IDENTIFIER_AVAILABLE;
		break;
	case OPT_SHARED_SUBSCRIPTION_AVAILABLE:
		prop_id = SHARED_SUBSCRIPTION_AVAILABLE;
		break;
	default:
		break;
	}

	return prop_id;
}

static int
properties_parse(int argc, char **argv, property *properties)
{
	int   idx = 1;
	char *arg;
	int   val;
	int   rv;

	uint8_t  u8;
	uint16_t u16;
	uint32_t u32;
	char *   str;
	char *   value;
	uint8_t *bin;

	property *prop_list = properties;
	property *prop_item;

	while ((rv = nng_opts_parse(
	            argc - 1, argv + 1, cmd_opts, &val, &arg, &idx)) == 0) {
		properties_type prop_id = properties_type_parse(val);
		if (prop_id == 0)
			continue;

		property_type_enum type =
		    mqtt_property_get_value_type(prop_id);
		switch (type) {
		case U8:
			u8        = (uint8_t) long_arg(arg, 0, UINT8_MAX);
			prop_item = mqtt_property_set_value_u8(prop_id, u8);
			break;
		case U16:
			u16       = (uint16_t) long_arg(arg, 0, UINT16_MAX);
			prop_item = mqtt_property_set_value_u16(prop_id, u16);
			break;
		case U32:
			u32       = (uint32_t) long_arg(arg, 0, UINT32_MAX);
			prop_item = mqtt_property_set_value_u32(prop_id, u32);
			break;
		case VARINT:
			u32 = (uint32_t) long_arg(arg, 0, UINT32_MAX);
			prop_item =
			    mqtt_property_set_value_varint(prop_id, u32);
			break;
		case BINARY:
			bin       = (uint8_t *) arg;
			prop_item = mqtt_property_set_value_binary(
			    prop_id, bin, strlen(arg), true);
			break;
		case STR:
			str       = arg;
			prop_item = mqtt_property_set_value_str(
			    prop_id, str, strlen(str), true);
			break;
		case STR_PAIR:
			str     = nng_zalloc(strlen(arg) + 1);
			value   = nng_zalloc(strlen(arg) + 1);
			int ret = sscanf(arg, "%[^=]=%s", str, value);
			if (ret != 2) {
				nng_free(str, strlen(str) + 1);
				nng_free(value, strlen(value) + 1);
				fatal("Invalid string pair: '%s', "
				      "Require "
				      "format: 'key=value'", arg);
			} else {
				prop_item = mqtt_property_set_value_strpair(
				    prop_id, str, strlen(str), value,
				    strlen(value), true);
				nng_free(str, strlen(str) + 1);
				nng_free(value, strlen(value) + 1);
			}

			break;

		default:
			fatal("Unknown property: %s", argv[idx]);
			break;
		}
		mqtt_property_append(prop_list, prop_item);
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

	return rv;
}

static void
set_default_conf(client_opts *opt)
{
	opt->total_msg_count = 1;
	opt->interval        = 10;
	opt->qos             = opts->type == SUB ? 2 : 0;
	opt->retain          = false;
	opt->parallel        = 1;
	opt->version         = 4;
	opt->keepalive       = 60;
	opt->clean_session   = true;
	opt->enable_ssl      = false;
	opt->verbose         = false;
	opt->stdin_line      = false;
	opt->topic_count     = 0;
	opt->clients         = 1;
	opt->conn_properties = NULL;
	opt->sub_properties  = NULL;
	opt->pub_properties  = NULL;
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
		if ((rv = nng_tls_config_own_cert(cfg, cert, key, pass)) !=
		    0) {
			goto out;
		}
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
publish_msg(client_opts *opt)
{
	// create a PUBLISH message
	nng_msg *pubmsg;
	property *props = NULL;
	nng_mqtt_msg_alloc(&pubmsg, 0);
	nng_mqtt_msg_set_packet_type(pubmsg, NNG_MQTT_PUBLISH);
	nng_mqtt_msg_set_publish_qos(pubmsg, opt->qos);
	nng_mqtt_msg_set_publish_retain(pubmsg, opt->retain);
	if (opt->stdin_line) {
		if (opt->msg)
			free(opt->msg);
		opt->msg = NULL;
		opt->msg_len = 0;
		size_t len;
		if ((opt->msg_len = nano_getline((char**) &(opt->msg), &len, stdin)) == -1) {
			console("Read line error!");
		} 
		opt->msg_len--;
	}
	nng_mqtt_msg_set_publish_payload(pubmsg, opt->msg, opt->msg_len);
	nng_mqtt_msg_set_publish_topic(pubmsg, opt->topic->val);
	if (opt->version == MQTT_PROTOCOL_VERSION_v5) {
		mqtt_property_dup(&props, opt->pub_properties);
		nng_mqtt_msg_set_publish_property(pubmsg, props);
	}

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
			nng_msg_clone(work->msg);
			nng_aio_set_msg(work->aio, work->msg);
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
			if (rv == NNG_ECONNSHUT) {
				work->msg = nng_aio_get_msg(work->aio);
				nng_msg_free(work->msg);
			} else if (rv == NNG_EINTERNAL) {
				nng_fatal("nng_recv_aio", rv);
			}
			work->state = INIT;
			nng_sleep_aio(1000, work->aio);
			break;
		}
		work->msg   = nng_aio_get_msg(work->aio);
		work->state = RECV_WAIT;
		nng_sleep_aio(0, work->aio);
		break;

	case RECV_WAIT:
		msg = work->msg;
		work->msg = NULL;
		uint32_t payload_len;
		uint8_t *payload =
		    nng_mqtt_msg_get_publish_payload(msg, &payload_len);
		uint32_t    topic_len;
		const char *recv_topic =
		    nng_mqtt_msg_get_publish_topic(msg, &topic_len);

		if (topic_len > 0) {
			console("%.*s: %.*s\n", topic_len, recv_topic,
			    payload_len, (char *) payload);
		}

		nng_msg_free(msg);

		work->state = RECV;
		nng_ctx_recv(work->ctx, work->aio);
		break;

	case SEND:
		if ((rv = nng_aio_result(work->aio)) != 0) {
			nng_msg_free(work->msg);
			nng_fatal("nng_send_aio", rv);
		}

		if (work->opts->stdin_line) {
			work->state = INIT;
			nng_sleep_aio(0, work->aio);
		} else {
			work->msg_count--;
			if (work->msg_count > 0) {
				nng_msg_clone(work->msg);
				nng_aio_set_msg(work->aio, work->msg);
				// nng_ctx_send(work->ctx, work->aio);
				work->state = SEND_WAIT;
				nng_sleep_aio(work->opts->interval, work->aio);
			} else {
				nng_socket_close(*work->sock);
				nng_closeall();
				exit(1);
			}
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
alloc_work(nng_socket sock, client_opts *opt)
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
	w->opts  = opt;
	w->state = INIT;
	return (w);
}

static nng_msg *
connect_msg(client_opts *opt)
{
	nng_msg *msg;
	nng_mqtt_msg_alloc(&msg, 0);
	nng_mqtt_msg_set_packet_type(msg, NNG_MQTT_CONNECT);
	nng_mqtt_msg_set_connect_proto_version(msg, opt->version);
	nng_mqtt_msg_set_connect_keep_alive(msg, opt->keepalive);
	nng_mqtt_msg_set_connect_clean_session(msg, opt->clean_session);
	nng_mqtt_msg_set_connect_property(msg, opt->conn_properties);

	if (opt->client_id) {
		nng_mqtt_msg_set_connect_client_id(msg, opt->client_id);
	}
	if (opt->user) {
		nng_mqtt_msg_set_connect_user_name(msg, opt->user);
	}
	if (opt->passwd) {
		nng_mqtt_msg_set_connect_password(msg, opt->passwd);
	}
	if (opt->will_topic) {
		nng_mqtt_msg_set_connect_will_topic(msg, opt->will_topic);
	}
	if (opt->will_qos) {
		nng_mqtt_msg_set_connect_will_qos(msg, opt->will_qos);
	}
	if (opt->will_msg) {
		nng_mqtt_msg_set_connect_will_msg(
		    msg, opt->will_msg, opt->will_msg_len);
	}
	if (opt->will_retain) {
		nng_mqtt_msg_set_connect_will_retain(msg, opt->will_retain);
	}

	return msg;
}

static void
connect_cb(nng_pipe p, nng_pipe_ev ev, void *arg)
{
	struct connect_param *param  = arg;
	int                   reason = 0;
	// get connect reason
	nng_pipe_get_int(p, NNG_OPT_MQTT_CONNECT_REASON, &reason);
	console("%s: %s connect result: %d \n", __FUNCTION__, param->opts->url,
	    reason);

	property *prop = NULL;
	if (param->opts->version == MQTT_PROTOCOL_VERSION_v5) {
		nng_pipe_get_ptr(
		    p, NNG_OPT_MQTT_CONNECT_PROPERTY, (void **) &prop);
	}

	if (reason == 0) {
		if (param->opts->type == SUB && param->opts->topic_count > 0) {
			nng_mqtt_topic_qos *topics_qos =
			    nng_mqtt_topic_qos_array_create(
			        param->opts->topic_count);
			size_t i = 0;
			for (struct topic *tp = param->opts->topic;
			     tp != NULL && i < param->opts->topic_count;
			     tp = tp->next, i++) {
				nng_mqtt_topic_qos_array_set(
				    topics_qos, i, tp->val, param->opts->qos, 1, 0, 0);
			}
			nng_mqtt_subscribe(*param->sock, topics_qos,
			    (uint32_t)param->opts->topic_count,
			    param->opts->sub_properties);
			nng_mqtt_topic_qos_array_free(
			    topics_qos, param->opts->topic_count);
		}
	}
}

// Disconnect message callback function
static void
disconnect_cb(nng_pipe p, nng_pipe_ev ev, void *arg)
{
	int reason = 0;
	// get connect reason
	nng_pipe_get_int(p, NNG_OPT_MQTT_DISCONNECT_REASON, &reason);
	// property *prop;
	// nng_pipe_get_ptr(p, NNG_OPT_MQTT_DISCONNECT_PROPERTY, &prop);
	// nng_socket_get?
	console("disconnected reason : %d\n", reason);
}

static int
quic_connect_cb(void *rmsg, void *arg)
{
	struct connect_param *param  = arg;
	int                   reason = 0;

	console("%s: %s connect\n", __FUNCTION__, param->opts->url);

	if (reason == 0) {
		if (param->opts->type == SUB && param->opts->topic_count > 0) {
			nng_mqtt_topic_qos *topics_qos =
			    nng_mqtt_topic_qos_array_create(
			        param->opts->topic_count);
			size_t i = 0;
			for (struct topic *tp = param->opts->topic;
			     tp != NULL && i < param->opts->topic_count;
			     tp = tp->next, i++) {
				nng_mqtt_topic_qos_array_set(
				    topics_qos, i, tp->val, param->opts->qos, 1, 0, 0);
			}
			nng_mqtt_subscribe(*param->sock, topics_qos,
			    (uint32_t)param->opts->topic_count,
			    param->opts->sub_properties);
			nng_mqtt_topic_qos_array_free(
			    topics_qos, param->opts->topic_count);
		}
	}


	return 0;
}

static int
quic_disconnect_cb(void *rmsg, void *arg)
{
	console("bridge client disconnected!\n");
	return 0;
}

static void
create_client(nng_socket *sock, struct work **works, size_t id, size_t nwork,
    struct connect_param *param, bool isquic)
{
	int        rv;
	nng_dialer dialer;

	if (isquic) {
#if defined(SUPP_QUIC)
		rv = param->opts->version == MQTT_PROTOCOL_VERSION_v5
		    ? nng_mqttv5_quic_client_open(sock)
		    : nng_mqtt_quic_client_open(sock);
		if (rv != 0) {
			nng_fatal("nng_socket", rv);
		}
		if (param->opts->version == MQTT_PROTOCOL_VERSION_v5) {
			nng_mqttv5_quic_set_connect_cb(sock, quic_connect_cb, param);
			nng_mqttv5_quic_set_disconnect_cb(sock, quic_disconnect_cb, param);
		} else {
			nng_mqtt_quic_set_connect_cb(sock, quic_connect_cb, param);
			nng_mqtt_quic_set_disconnect_cb(sock, quic_disconnect_cb, param);
		}
#else
		console("Enable NNG_ENABLE_QUIC=ON in cmake first");
#endif
	} else {
		rv = param->opts->version == MQTT_PROTOCOL_VERSION_v5
		    ? nng_mqttv5_client_open(sock)
		    : nng_mqtt_client_open(sock);
		if (rv != 0) {
			nng_fatal("nng_socket", rv);
		}
		nng_mqtt_set_connect_cb(*sock, connect_cb, param);
		nng_mqtt_set_disconnect_cb(*sock, disconnect_cb, conn_msg);
	}

	for (size_t i = 0; i < opts->parallel; i++) {
		works[i] = alloc_work(*sock, opts);
		works[i]->sock = sock;
	}

	conn_msg = connect_msg(opts);

	if ((rv = nng_dialer_create(&dialer, *sock, opts->url)) != 0) {
		nng_fatal("nng_dialer_create", rv);
	}

#ifdef NNG_SUPP_TLS
	if (opts->enable_ssl) {
		if ((rv = init_dialer_tls(dialer, opts->cacert, opts->cert,
		         opts->key, opts->keypass)) != 0) {
			nng_fatal("init_dialer_tls", rv);
		}
	}
#endif

	nng_dialer_set_ptr(dialer, NNG_OPT_MQTT_CONNMSG, conn_msg);
	// nng_dialer_set_bool(dialer, NNG_OPT_QUIC_ENABLE_0RTT, true);
	// by set NNG_OPT_MQTT_CONNMSG for socket, it enables online/offline msg
	// nng_socket_set_ptr(*sock, NNG_OPT_MQTT_CONNMSG, conn_msg);

	param->sock = sock;
	param->opts = opts;
	param->id   = id;

	if ((rv = nng_dialer_start(dialer, NNG_FLAG_ALLOC)) != 0) {
		nng_fatal("nng_dialer_start", rv);
	}

	average_msgs(opts, works);
	for (size_t i = 0; i < opts->parallel; i++) {
		client_cb(works[i]);
	}
}

static void
average_msgs(client_opts *opt, struct work **works)
{
	size_t total_msgs   = opt->total_msg_count;
	size_t remainder    = total_msgs % opt->parallel;
	size_t average_msgs = total_msgs / opt->parallel;
	for (size_t i = 0; i < opt->parallel; i++) {
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
	opts->type = type;
	set_default_conf(opts);

	client_parse_opts(argc, argv, opts);

	if (opts->version == MQTT_PROTOCOL_VERSION_v5) {
		property *properties = mqtt_property_alloc();
		properties_parse(argc, argv, properties);
		properties_classify(properties, opts);
		mqtt_property_free(properties);
	}

	if (opts->interval == 0 && opts->total_msg_count > 0) {
		opts->interval = 1;
	}
	if (opts->total_msg_count < opts->parallel) {
		opts->parallel = opts->total_msg_count;
	}
	if (opts->version == 3) {
		opts->version = 4;
	}

	struct connect_param **param =
	    nng_zalloc(sizeof(struct connect_param *) * opts->clients);
	nng_socket **socket = nng_zalloc(sizeof(nng_socket *) * opts->clients);

	struct work ***works =
	    nng_zalloc(sizeof(struct work **) * opts->clients);

	bool isquic = false;

	if (strncmp("mqtt-quic", opts->url, 9) == 0) {
#if !defined(SUPP_QUIC)
		fatal("Quic client is disabled for now !\nPlease recompile "
		      "nanomq_cli "
		      "with option `-DNNG_ENABLE_QUIC=ON` to Enable Quic "
		      "support");
#endif
		isquic = true;
	}

	for (size_t i = 0; i < opts->clients; i++) {
		param[i]       = nng_zalloc(sizeof(struct connect_param));
		param[i]->opts = opts;
		socket[i]      = nng_zalloc(sizeof(nng_socket));
		works[i] = nng_zalloc(sizeof(struct work **) * opts->parallel);

		create_client(
		    socket[i], works[i], i, opts->parallel, param[i], isquic);
		nng_msleep(opts->interval);
	}

	for (;;) {
		nng_msleep(1000);
	}

	for (size_t j = 0; j < opts->clients; j++) {
		nng_free(param[j], sizeof(struct connect_param));
		nng_free(socket[j], sizeof(nng_socket));
		console("cleaning all clients!\n");

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

	free_opts();
}

int
publish_start(int argc, char **argv)
{
	client(argc, argv, PUB);
	free_opts();
	return 0;
}

int
subscribe_start(int argc, char **argv)
{
	client(argc, argv, SUB);
	free_opts();
	return 0;
}

int
connect_start(int argc, char **argv)
{
	client(argc, argv, CONN);
	return 0;
}

static void
free_opts(void)
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
		if (opts->conn_properties) {
			mqtt_property_free(opts->conn_properties);
		}
		if (opts->sub_properties) {
			mqtt_property_free(opts->sub_properties);
		}
		if (opts->pub_properties) {
			mqtt_property_free(opts->pub_properties);
		}

		free(opts);
	}
}

#endif
