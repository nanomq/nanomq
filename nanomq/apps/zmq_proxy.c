#include "zmq_proxy.h"
#include <zmq.h>
#include "include/nanomq.h"
#include "zmalloc.h"

struct work {
	enum { INIT, RECV, WAIT, SEND } state;
	nng_aio *aio;
	nng_msg *msg;
	nng_ctx  ctx;
};

static zmq_proxy_conf *conf_g = NULL;
static int nwork = 32;

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

void set_sub_topic(nng_mqtt_topic_qos topic_qos[], int qos, char **topic_que)
{
  	// for (int i = 0; i < TOPIC_CNT; i++) {
  		topic_qos[0].qos = qos;
        printf("topic: %s\n", topic_que[0]);
  		topic_qos[0].topic.buf = (uint8_t*) topic_que[0];
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
  	topic_qos[0].qos = 0;
  	topic_qos[0].topic.buf = (uint8_t*) conf_g->sub_topic;
  	topic_qos[0].topic.length = strlen(conf_g->sub_topic);

	size_t topic_qos_count =
	    sizeof(topic_qos) / sizeof(nng_mqtt_topic_qos);

	nng_msg *msg;
	nng_mqtt_msg_alloc(&msg, 0);
	nng_mqtt_msg_set_packet_type(msg, NNG_MQTT_SUBSCRIBE);
	nng_mqtt_msg_set_subscribe_topics(msg, topic_qos, topic_qos_count);

	// Send subscribe message
	int rv  = 0;
	while ((rv = nng_sendmsg(sock, msg, NNG_FLAG_NONBLOCK)) != 0) {
		proxy_fatal("nng_sendmsg", rv);
		sleep(1);
	}
}

int check_recv(nng_msg *msg)
{

	// Get PUBLISH payload and topic from msg;
	uint32_t payload_len;
	uint32_t topic_len;

	uint8_t *payload = nng_mqtt_msg_get_publish_payload(msg, &payload_len);
	const char *topic = nng_mqtt_msg_get_publish_topic(msg, &topic_len);
	// printf("RECV: '%.*s' FROM: '%.*s'\n", payload_len,
	//     (char *) payload, topic_len, topic);

    zmq_send(conf_g->zmq_sender, (void*) payload, payload_len, 0);

	// char topic_buf[TOPIC_LEN];
	// char payload_buf[TOPIC_LEN];
	
	// memcpy(topic_buf, topic, topic_len);
	// memcpy(payload_buf, payload, payload_len);
	// payload_buf[TOPIC_LEN-1] = '\0';
	// topic_buf[TOPIC_LEN-1] = '\0';
	

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
		msg   = nng_aio_get_msg(work->aio);

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

	for (int i = 0; i < nwork; i++) {
		works[i] = proxy_alloc_work(sock);
	}

	// Mqtt connect message
	nng_msg *msg;
	nng_mqtt_msg_alloc(&msg, 0);
	nng_mqtt_msg_set_packet_type(msg, NNG_MQTT_CONNECT);
	nng_mqtt_msg_set_connect_keep_alive(msg, 60);
	nng_mqtt_msg_set_connect_clean_session(msg, false);
	nng_mqtt_msg_set_connect_user_name(msg, "nng_mqtt_client");
	nng_mqtt_msg_set_connect_password(msg, "secrets");

	nng_mqtt_set_connect_cb(sock, connect_cb, &sock);
	nng_mqtt_set_disconnect_cb(sock, disconnect_cb, NULL);

	if ((rv = nng_dialer_create(&dialer, sock, url)) != 0) {
		proxy_fatal("nng_dialer_create", rv);
	}

	nng_dialer_set_ptr(dialer, NNG_OPT_MQTT_CONNMSG, msg);
	nng_dialer_start(dialer, NNG_FLAG_NONBLOCK);

	for (int i = 0; i < nwork; i++) {
		gateway_sub_cb(works[i]);
	}

    *sock_ret = sock;
	return 0;
}

int zmq_gateway(zmq_proxy_conf *conf)
{
    nng_socket sock;
    void *receiver = NULL;
    void *sender = NULL;
    void *context = zmq_ctx_new();
    if (conf->type == PUB_SUB) {
        receiver = zmq_socket(context, ZMQ_SUB);
        sender = zmq_socket(context, ZMQ_PUB);
    } else if (conf->type == REQ_REP) {
        receiver = zmq_socket(context, ZMQ_REP);
        sender = zmq_socket(context, ZMQ_REQ);
    }

    // zmq_connect(receiver, conf->zmq_url);
    zmq_connect(receiver, conf->zmq_conn_url);
	zmq_setsockopt(receiver, ZMQ_SUBSCRIBE, "", 0);

    zmq_bind(sender, conf->zmq_listen_url);
    conf->zmq_sender = sender;
    client(conf->mqtt_url, &sock);

    while (1) {
        char msg [256];
        int size = zmq_recv(receiver, msg, 255, 0);
		printf("recv: %.*s\n", size, msg);
        if (size != -1) {
	        client_publish(sock, conf->pub_topic, (uint8_t*) msg, size, 0, false);
        }
    }

    zmq_close (receiver);
    zmq_ctx_destroy (context);
}

static zmq_proxy_conf *read_conf(const char *pwd)
{
    zmq_proxy_conf *conf = (zmq_proxy_conf *) zmalloc(sizeof(zmq_proxy_conf));
    if (conf == NULL) {
        fprintf(stderr, "Memory alloc error.\n");
        exit(EXIT_FAILURE);
    }
    conf->mqtt_url = zstrdup("mqtt-tcp://localhost:1883");
    conf->zmq_listen_url = zstrdup("tcp://*:5559");
    conf->zmq_conn_url = zstrdup("tcp://localhost:5560");
    conf->pub_topic = zstrdup("topic/pub");
    conf->sub_topic = zstrdup("topic/sub");

    conf->type = PUB_SUB;
    conf->zmq_sender = NULL;
    return conf;

}

int gateway_start(int argc, char **argv)
{
    const char *pwd = "";
    // TODO read config
    zmq_proxy_conf *conf = read_conf(pwd);
	conf_g = conf;
    zmq_gateway(conf);
    return 0;
}
int gateway_dflt(int argc, char **argv)
{
    printf("gateway help info!");
    // TODO

    return 0;
}