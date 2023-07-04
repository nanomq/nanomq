#if defined(SUPP_ZMQ_GATEWAY)
#include "zmq_gateway.h"
#include "nng/nng.h"
#include "nng/supplemental/nanolib/conf.h"
#include "nng/supplemental/util/options.h"
#include <zmq.h>
#include "web_server.h"

struct work {
	enum { INIT, RECV, WAIT, SEND } state;
	nng_aio *aio;
	nng_msg *msg;
	nng_ctx  ctx;
};

enum options {
	OPT_HELP = 1,
	OPT_CONFFILE,
};

static nng_optspec cmd_opts[] = {
	{ .o_name = "help", .o_short = 'h', .o_val = OPT_HELP },
	{ .o_name = "conf", .o_val = OPT_CONFFILE, .o_arg = true },
	{ .o_name = NULL, .o_val = 0 },
};

static char help_info[] =
    "Usage: nanomq_cli zmq_gateway [--conf <path>]\n\n"
    "  --conf <path>  The path of a specified nanomq configuration file \n";

static zmq_gateway_conf *conf_g = NULL;
static int               nwork  = 32;

void
proxy_fatal(const char *msg, int rv)
{
	fprintf(stderr, "%s: %s\n", msg, nng_strerror(rv));
}

void
disconnect_cb(nng_pipe p, nng_pipe_ev ev, void *arg)
{
	printf("%s: disconnected!\n", __FUNCTION__);
}

void
set_sub_topic(nng_mqtt_topic_qos topic_qos[], int qos, char **topic_que)
{
	// for (int i = 0; i < TOPIC_CNT; i++) {
	topic_qos[0].qos = qos;
	printf("topic: %s\n", topic_que[0]);
	topic_qos[0].topic.buf    = (uint8_t *) topic_que[0];
	topic_qos[0].topic.length = strlen(topic_que[0]);
	// }
	return;
}

void
connect_cb(nng_pipe p, nng_pipe_ev ev, void *arg)
{
	printf("%s: connected!\n", __FUNCTION__);
	nng_socket sock = *(nng_socket *) arg;

	nng_mqtt_topic_qos topic_qos[1];

	// set_sub_topic(topic_qos, 0, &conf->sub_topic);
	printf("topic: %s\n", conf_g->sub_topic);
	topic_qos[0].qos          = 0;
	topic_qos[0].topic.buf    = (uint8_t *) conf_g->sub_topic;
	topic_qos[0].topic.length = strlen(conf_g->sub_topic);

	size_t topic_qos_count =
	    sizeof(topic_qos) / sizeof(nng_mqtt_topic_qos);

	nng_msg *msg;
	nng_mqtt_msg_alloc(&msg, 0);
	nng_mqtt_msg_set_packet_type(msg, NNG_MQTT_SUBSCRIBE);
	nng_mqtt_msg_set_subscribe_topics(msg, topic_qos, topic_qos_count);

	// Send subscribe message
	int rv = 0;
	rv     = nng_sendmsg(sock, msg, NNG_FLAG_NONBLOCK);
	if (rv != 0) {
		proxy_fatal("nng_sendmsg", rv);
	}
}

int
check_recv(nng_msg *msg)
{

	// Get PUBLISH payload and topic from msg;
	uint32_t payload_len;
	uint32_t topic_len;

	uint8_t *payload = nng_mqtt_msg_get_publish_payload(msg, &payload_len);
	const char *topic = nng_mqtt_msg_get_publish_topic(msg, &topic_len);
	// printf("RECV: '%.*s' FROM: '%.*s'\n", payload_len,
	//     (char *) payload, topic_len, topic);

	if (conf_g->zmq_pub_pre) {
		zmq_send(conf_g->zmq_sender, (void *) conf_g->zmq_pub_pre,
		    strlen(conf_g->zmq_pub_pre), ZMQ_SNDMORE);
	}
	zmq_send(conf_g->zmq_sender, (void *) payload, payload_len, 0);

	return 0;
}

void
gateway_sub_cb(void *arg)
{
	struct work *work = arg;
	nng_msg *    msg;
	int          rv;

	switch (work->state) {
	case INIT:
		work->state = RECV;
		nng_ctx_recv(work->ctx, work->aio);
		break;
	case RECV:
		if ((rv = nng_aio_result(work->aio)) != 0) {
			nng_msg_free(work->msg);
			proxy_fatal("nng_send_aio", rv);
		}
		msg = nng_aio_get_msg(work->aio);

		if (-1 == check_recv(msg)) {
			abort();
		}

		work->state = RECV;
		nng_ctx_recv(work->ctx, work->aio);
		break;
	default:
		proxy_fatal("bad state!", NNG_ESTATE);
		break;
	}
}

struct work *
proxy_alloc_work(nng_socket sock)
{
	struct work *w;
	int          rv;

	if ((w = nng_alloc(sizeof(*w))) == NULL) {
		proxy_fatal("nng_alloc", NNG_ENOMEM);
	}
	if ((rv = nng_aio_alloc(&w->aio, gateway_sub_cb, w)) != 0) {
		proxy_fatal("nng_aio_alloc", rv);
	}
	if ((rv = nng_ctx_open(&w->ctx, sock)) != 0) {
		proxy_fatal("nng_ctx_open", rv);
	}
	w->state = INIT;
	return (w);
}

int
client_publish(nng_socket sock, const char *topic, uint8_t *payload,
    uint32_t payload_len, uint8_t qos, bool verbose)
{
	int rv;

	// create a PUBLISH message
	nng_msg *pubmsg;
	nng_mqtt_msg_alloc(&pubmsg, 0);
	nng_mqtt_msg_set_packet_type(pubmsg, NNG_MQTT_PUBLISH);
	nng_mqtt_msg_set_publish_dup(pubmsg, 0);
	nng_mqtt_msg_set_publish_qos(pubmsg, qos);
	nng_mqtt_msg_set_publish_retain(pubmsg, 0);
	nng_mqtt_msg_set_publish_payload(
	    pubmsg, (uint8_t *) payload, payload_len);
	nng_mqtt_msg_set_publish_topic(pubmsg, topic);

	// printf("Publishing '%s' to '%s' ...\n", payload, topic);
	if ((rv = nng_sendmsg(sock, pubmsg, NNG_FLAG_NONBLOCK)) != 0) {
		proxy_fatal("nng_sendmsg", rv);
	}

	return rv;
}

int
client(const char *url, nng_socket *sock_ret)
{
	nng_socket   sock;
	nng_dialer   dialer;
	int          rv;
	struct work *works[nwork];

	if ((rv = nng_mqtt_client_open(&sock)) != 0) {
		proxy_fatal("nng_socket", rv);
		return rv;
	}

	*sock_ret = sock;

	for (int i = 0; i < nwork; i++) {
		works[i] = proxy_alloc_work(sock);
	}

	// Mqtt connect message
	nng_msg *msg;
	nng_mqtt_msg_alloc(&msg, 0);
	nng_mqtt_msg_set_packet_type(msg, NNG_MQTT_CONNECT);
	nng_mqtt_msg_set_connect_proto_version(msg, conf_g->proto_ver);
	nng_mqtt_msg_set_connect_keep_alive(msg, conf_g->keepalive);
	nng_mqtt_msg_set_connect_clean_session(msg, conf_g->clean_start);
	if (conf_g->username) {
		nng_mqtt_msg_set_connect_user_name(msg, conf_g->username);
	}

	if (conf_g->password) {
		nng_mqtt_msg_set_connect_password(msg, conf_g->password);
	}

	nng_mqtt_set_connect_cb(sock, connect_cb, sock_ret);
	nng_mqtt_set_disconnect_cb(sock, disconnect_cb, NULL);

	if ((rv = nng_dialer_create(&dialer, sock, url)) != 0) {
		proxy_fatal("nng_dialer_create", rv);
	}

	nng_dialer_set_ptr(dialer, NNG_OPT_MQTT_CONNMSG, msg);
	nng_dialer_start(dialer, NNG_FLAG_NONBLOCK);

	for (int i = 0; i < nwork; i++) {
		gateway_sub_cb(works[i]);
	}

	return 0;
}

int
zmq_gateway(zmq_gateway_conf *conf)
{
	nng_socket sock;
	void *     receiver = NULL;
	void *     sender   = NULL;
	void *     context  = zmq_ctx_new();
	if (conf->type == PUB_SUB) {
		receiver = zmq_socket(context, ZMQ_SUB);
		sender   = zmq_socket(context, ZMQ_PUB);
	} else if (conf->type == REQ_REP) {
		receiver = zmq_socket(context, ZMQ_REP);
		sender   = zmq_socket(context, ZMQ_REQ);
	}

	zmq_connect(receiver, conf->zmq_sub_url);
	if (conf->zmq_sub_pre == NULL) {
		conf->zmq_sub_pre = "";
	}
	zmq_setsockopt(receiver, ZMQ_SUBSCRIBE, conf->zmq_sub_pre,
	    strlen(conf->zmq_sub_pre));

	// zmq_bind(sender, conf->zmq_listen_url);
	zmq_connect(sender, conf->zmq_pub_url);
	conf->zmq_sender = sender;
	client(conf->mqtt_url, &sock);

	while (1) {
		zmq_msg_t message;
		zmq_msg_init(&message);
		zmq_msg_recv(&message, receiver, 0);
		int more = zmq_msg_more(&message);
		// printf("recv: %.*s\n", (int) zmq_msg_size(&message), (char*)
		// zmq_msg_data(&message));
		client_publish(sock, conf->pub_topic,
		    (uint8_t *) zmq_msg_data(&message), zmq_msg_size(&message),
		    0, false);
		zmq_msg_close(&message);
	}

	zmq_close(receiver);
	zmq_ctx_destroy(context);
}

static void
gateway_conf_init(zmq_gateway_conf *conf)
{
	conf->mqtt_url    = NULL;
	conf->zmq_pub_url = NULL;
	conf->zmq_sub_url = NULL;
	conf->pub_topic   = NULL;
	conf->sub_topic   = NULL;
	conf->zmq_sub_pre = NULL;
	conf->zmq_pub_pre = NULL;
	conf->type        = PUB_SUB;
	conf->zmq_sender  = NULL;
	conf->username    = NULL;
	conf->password    = NULL;
	conf->proto_ver   = 4;
	conf->keepalive   = 60;
	return;
}

static int
gateway_conf_check_and_set(zmq_gateway_conf *conf)
{
	if (!conf->sub_topic || !conf->pub_topic) {
		fprintf(stderr, "Pls set sub/pub topic before.");
		return -1;
	}
	if (conf->mqtt_url == NULL) {
		conf->mqtt_url ? conf->mqtt_url
		               : nng_strdup("mqtt-tcp://broker.emqx.io:1883");
		printf("Set default mqtt-url: %s\n", conf->mqtt_url);
	}
	if (conf->zmq_pub_url == NULL) {
		conf->zmq_pub_url ? conf->zmq_pub_url
		                  : nng_strdup("tcp://localhost:5559");
		printf("Set default zmq-pub-url: %s\n", conf->zmq_pub_url);
	}
	if (conf->zmq_sub_url == NULL) {
		conf->zmq_sub_url ? conf->zmq_sub_url
		                  : nng_strdup("tcp://localhost:5560");
		printf("Set default zmq-sub-url: %s\n", conf->zmq_sub_url);
	}

	nwork  = conf->parallel;
	conf_g = conf;
	return 0;
}

int
gateway_parse_opts(int argc, char **argv, zmq_gateway_conf *config)
{
	int   idx = 1;
	char *arg;
	int   val;
	int   rv;

	while ((rv = nng_opts_parse(
	            argc - 1, argv + 1, cmd_opts, &val, &arg, &idx)) == 0) {
		switch (val) {
		case OPT_HELP:
			printf("%s", help_info);
			exit(0);
			break;
		case OPT_CONFFILE:
			config->path = nng_strdup(arg);
			break;
		default:
			break;
		}
	}

	switch (rv) {
	case NNG_EINVAL:
		fprintf(stderr,
		    "Option %s is invalid.\nTry 'nanomq_cli gateway --help' for "
		    "more information.\n",
		    argv[idx]);
		break;
	case NNG_EAMBIGUOUS:
		fprintf(stderr,
		    "Option %s is ambiguous (specify in full).\nTry 'nanomq_cli "
		    "gateway --help' for more information.\n",
		    argv[idx]);
		break;
	case NNG_ENOARG:
		fprintf(stderr,
		    "Option %s requires argument.\nTry 'nanomq_cli gateway "
		    "--help' "
		    "for more information.\n",
		    argv[idx]);
		break;
	default:
		break;
	}

	return rv == -1;
}

int
gateway_start(int argc, char **argv)
{
	zmq_gateway_conf *conf =
	    (zmq_gateway_conf *) nng_alloc(sizeof(zmq_gateway_conf));
	if (conf == NULL) {
		fprintf(stderr, "Memory alloc error.\n");
		exit(EXIT_FAILURE);
	}

	gateway_conf_init(conf);
	gateway_parse_opts(argc, argv, conf);
	conf_gateway_parse_ver2(conf);
	if (conf->http_server.enable) {
		proxy_info *info = proxy_info_alloc(PROXY_NAME_ZEROMQ, conf,
		    conf->path, &conf->http_server, argc, argv);
		start_rest_server(info);
	}
	if (-1 != gateway_conf_check_and_set(conf)) {
		zmq_gateway(conf);
	}
	return 0;
}
int
gateway_dflt(int argc, char **argv)
{
	printf("%s", help_info);
	return 0;
}
#endif
