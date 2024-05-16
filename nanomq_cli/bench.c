#if !defined(NANO_PLATFORM_WINDOWS) && defined(SUPP_BENCH)
//TODO support windows later
#include "include/nnb_opt.h"
#include <limits.h>
#include <nng/nng.h>
#include <nng/supplemental/tls/tls.h>
#include <nng/supplemental/util/options.h>
#include <nng/supplemental/util/platform.h>
#include "nng/supplemental/nanolib/utils.h"
#include <stdarg.h>

#ifndef PARALLEL
#define PARALLEL 8
#endif

typedef struct {
	nng_atomic_int *acnt;
	nng_atomic_int *topic_cnt;
	nng_atomic_int *recv_cnt;
	nng_atomic_int *last_recv_cnt;
	nng_atomic_int *send_cnt;
	nng_atomic_int *send_limit;
	nng_atomic_int *last_send_cnt;
	nng_atomic_int *index_cnt;
} bench_statistics;

typedef enum { INIT, RECV, WAIT, SEND } nnb_state_flag_t;

typedef enum {
	CONN,
	SUB,
	PUB,
} nnb_opt_flag_t;

struct work {
	nng_aio *        aio;
	nng_msg *        msg;
	nng_time         last_send_ts; // last logical time stamp we send
	nng_ctx          ctx;
	nnb_state_flag_t state;
};

static nnb_opt_flag_t opt_flag = CONN;
static nnb_sub_opt *  sub_opt  = NULL;
static nnb_pub_opt *  pub_opt  = NULL;

static bench_statistics statistics;

static void
bench_count_init(bench_statistics *bs)
{
	nng_atomic_alloc(&bs->acnt);
	nng_atomic_alloc(&bs->topic_cnt);
	nng_atomic_alloc(&bs->recv_cnt);
	nng_atomic_alloc(&bs->last_recv_cnt);
	nng_atomic_alloc(&bs->send_cnt);
	nng_atomic_alloc(&bs->send_limit);
	nng_atomic_alloc(&bs->last_send_cnt);
	nng_atomic_alloc(&bs->index_cnt);
}

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

char *
nnb_opt_get_topic(char *opt_topic, char *opt_username, nng_msg *msg)
{
	char *topic = NULL;
	if ((topic = strstr(opt_topic, "\%c")) != NULL) {
		int         len = topic - opt_topic + 1;
		const char *client_id =
		    nng_mqtt_msg_get_connect_client_id(msg);
		size_t size = len + strlen(client_id) + 1;
		topic       = (char *) nng_alloc(sizeof(char) * size);
		char *t     = (char *) nng_alloc(sizeof(char) * len);
		snprintf(t, len, "%s", opt_topic);
		snprintf(topic, size, "%s%s", t, client_id);
		nng_free(t, len);
	} else if ((topic = strstr(opt_topic, "\%u")) != NULL) {
		int    len      = topic - opt_topic + 1;
		char * username = opt_username ? opt_username : "undefined";
		size_t size     = len + strlen(username) + 1;
		topic           = (char *) nng_alloc(sizeof(char) * size);
		char *t         = (char *) nng_alloc(sizeof(char) * len);
		snprintf(t, len, "%s", opt_topic);
		snprintf(topic, size, "%s%s", t, username);
		nng_free(t, len);
	} else if ((topic = strstr(opt_topic, "\%i")) != NULL) {
		int    len  = topic - opt_topic + 1;
		size_t size = len + 5;
		topic       = (char *) nng_alloc(sizeof(char) * size);
		char *t     = (char *) nng_alloc(sizeof(char) * len);
		snprintf(t, len, "%s", opt_topic);
		snprintf(topic, size, "%s%d", t,
		    nng_atomic_get(statistics.topic_cnt));
		nng_atomic_inc(statistics.topic_cnt);
		nng_free(t, len);
	} else {
		return opt_topic;
	}
	return topic;
}

void
sub_cb(void *arg)
{
	struct work *work = arg;
	nng_msg *    msg;
	int          rv;

	switch (work->state) {
	case INIT:
		// subscribe to topics
		if (nng_atomic_get(statistics.index_cnt) == 0) {
			nng_mqtt_msg_alloc(&msg, 0);
			nng_mqtt_msg_set_packet_type(msg, NNG_MQTT_SUBSCRIBE);
			char *topic = nnb_opt_get_topic(
			    sub_opt->topic, sub_opt->username, work->msg);
			printf("Subscribe topic: %s\n", topic);
			nng_mqtt_topic_qos topic_qos[] = {
				{ .qos     = sub_opt->qos,
				    .topic = { .buf = (uint8_t *) topic,
				        .length     = strlen(topic) } },
			};

			nng_mqtt_msg_set_subscribe_topics(msg, topic_qos, 1);
			nng_aio_set_msg(work->aio, msg);
			work->state = SEND;
			nng_ctx_send(work->ctx, work->aio);
		} else {
			work->state = RECV;
			nng_ctx_recv(work->ctx, work->aio);
		}
		break;

	case SEND:
		// we are done with subscribing
		if ((rv = nng_aio_result(work->aio)) != 0) {
			nng_msg_free(work->msg);
			nng_fatal("nng_send_aio", rv);
		}
		work->state = RECV;
		nng_ctx_recv(work->ctx, work->aio);
		break;

	case RECV:
		// forever receiving
		if ((rv = nng_aio_result(work->aio)) != 0) {
			nng_fatal("nng_recv_aio", rv);
		}
		nng_atomic_inc(statistics.recv_cnt);
		msg         = nng_aio_get_msg(work->aio);
		nng_msg_free(msg);
		work->state = RECV;
		nng_ctx_recv(work->ctx, work->aio);
		break;

	default:
		break;
	}
}

void
pub_cb(void *arg)
{
	struct work *work = arg;
	nng_msg *    msg;
	int          rv;

	switch (work->state) {
	case INIT:
		nng_atomic_inc(statistics.send_cnt);
		if (nng_atomic_get(statistics.send_cnt) >
		    nng_atomic_get(statistics.send_limit)) {
			break;
		}
		// nng_mqtt_msg_alloc(&work->msg, 0);
		nng_mqtt_msg_set_packet_type(work->msg, NNG_MQTT_PUBLISH);
		if (work->msg == NULL) { }
		char *topic = nnb_opt_get_topic(
		    pub_opt->topic, pub_opt->username, work->msg);
		nng_mqtt_msg_set_publish_topic(work->msg, topic);
		nng_mqtt_msg_set_publish_qos(work->msg, pub_opt->qos);
		nng_mqtt_msg_set_publish_retain(work->msg, pub_opt->retain);
		char *payload =
		    (char *) nng_alloc(sizeof(char) * pub_opt->size);
		memset(payload, 'A', pub_opt->size);
		nng_mqtt_msg_set_publish_payload(
		    work->msg, (uint8_t *) payload, pub_opt->size);
		nng_mqtt_msg_encode(work->msg);

		nng_msg_dup(&msg, work->msg);
		nng_aio_set_msg(work->aio, msg);
		msg                = NULL;
		work->state        = WAIT;
		work->last_send_ts = nng_clock();
		nng_ctx_send(work->ctx, work->aio);
		break;

	case WAIT:
		work->state = SEND;
		// NOTE: nng_sleep_aio will sleep for more than you wanted
		if (pub_opt->interval_of_msg >= 1) {
			nng_time now      = nng_clock();
			int      interval = pub_opt->interval_of_msg;
			long     d = now - work->last_send_ts - interval;
			// increment the logic clock
			work->last_send_ts += interval;
			if (d < interval) {
				// not too much delay, just sleep
				nng_sleep_aio(interval, work->aio);
				break;
			}

			// we have slept too much, just to SEND
		}

		// do not call sleep for a zero interval_of_msg

		// fall through

	case SEND:
		// send packets
		if ((rv = nng_aio_result(work->aio)) != 0) {
			nng_msg_free(work->msg);
			nng_fatal("nng_send_aio", rv);
		}
		nng_atomic_inc(statistics.send_cnt);
		if (nng_atomic_get(statistics.send_cnt) >
		    nng_atomic_get(statistics.send_limit)) {
			break;
		}
		nng_msg_dup(&msg, work->msg);
		nng_aio_set_msg(work->aio, msg);
		msg         = NULL;
		work->state = WAIT;
		nng_ctx_send(work->ctx, work->aio);
		break;

	default:
		break;
	}
}

static struct work *
alloc_work(nng_socket sock, void cb(void *))
{
	struct work *w;
	int          rv;

	if ((w = nng_alloc(sizeof(*w))) == NULL) {
		nng_fatal("nng_alloc", NNG_ENOMEM);
	}
	if ((rv = nng_aio_alloc(&w->aio, cb, w)) != 0) {
		nng_fatal("nng_aio_alloc", rv);
	}
	if ((rv = nng_ctx_open(&w->ctx, sock)) != 0) {
		nng_fatal("nng_ctx_open", rv);
	}
	w->state = INIT;
	return (w);
}

// Connack message callback function
static void
connect_cb(nng_pipe p, nng_pipe_ev ev, void *arg)
{
	switch (opt_flag) {
	case SUB:;
		nng_atomic_inc(statistics.acnt);
		printf("connected: %d.\n", nng_atomic_get(statistics.acnt));
		break;
	case PUB:
		nng_atomic_inc(statistics.acnt);
		printf("connected: %d.\n", nng_atomic_get(statistics.acnt));
		break;
	case CONN:
		nng_atomic_inc(statistics.acnt);
		printf("connected: %d.\n", nng_atomic_get(statistics.acnt));
		break;
	}
}

static void
disconnect_cb(nng_pipe p, nng_pipe_ev ev, void *arg)
{
	printf("disconnected!\n");
}

int
nnb_connect(nnb_conn_opt *opt)
{
	if (opt == NULL) {
		fprintf(stderr, "Connection parameters init failed!\n");
	}

	char       url[255];
	nng_socket sock;
	nng_dialer dialer;
	int        i;
	int        rv;

	if (opt->tls.enable) {
		sprintf(url, "tls+mqtt-tcp://%s:%d", opt->host, opt->port);
	} else {
		sprintf(url, "mqtt-tcp://%s:%d", opt->host, opt->port);
	}

	rv = opt->version == 5 ? nng_mqttv5_client_open(&sock)
	                       : nng_mqtt_client_open(&sock);

	if (rv != 0) {
		nng_fatal("nng_socket", rv);
	}

	if ((rv = nng_dialer_create(&dialer, sock, url)) != 0) {
		nng_fatal("nng_dialer_create", rv);
	}

	if (opt->tls.enable) {
		if ((rv = init_dialer_tls(dialer, opt->tls.cacert,
		              opt->tls.cert, opt->tls.key,
		              opt->tls.keypass) != 0)) {
			nng_fatal("init_dialer_tls", rv);
		}
	}

	// Mqtt connect message
	nng_msg *msg;
	nng_mqtt_msg_alloc(&msg, 0);
	nng_mqtt_msg_set_packet_type(msg, NNG_MQTT_CONNECT);
	nng_mqtt_msg_set_connect_proto_version(msg, opt->version);
	nng_mqtt_msg_set_connect_keep_alive(msg, opt->keepalive);
	nng_mqtt_msg_set_connect_clean_session(msg, opt->clean);

	nng_mqtt_set_connect_cb(sock, connect_cb, &sock);
	nng_mqtt_set_disconnect_cb(sock, disconnect_cb, NULL);

	if (opt->username) {
		nng_mqtt_msg_set_connect_user_name(msg, opt->username);
	}
	if (opt->password) {
		nng_mqtt_msg_set_connect_password(msg, opt->password);
	}

	nng_dialer_set_ptr(dialer, NNG_OPT_MQTT_CONNMSG, msg);
	nng_dialer_start(dialer, NNG_FLAG_NONBLOCK);
	return 0;
}

int
nnb_subscribe(nnb_sub_opt *opt)
{
	if (opt == NULL) {
		fprintf(stderr, "Connection parameters init failed!\n");
	}

	char         url[255];
	nng_socket   sock;
	nng_dialer   dialer;
	struct work *works[PARALLEL];
	int          i;
	int          rv;

	if (opt->tls.enable) {
		sprintf(url, "tls+mqtt-tcp://%s:%d", opt->host, opt->port);
	} else {
		sprintf(url, "mqtt-tcp://%s:%d", opt->host, opt->port);
	}

	rv = opt->version == 5 ? nng_mqttv5_client_open(&sock)
	                       : nng_mqtt_client_open(&sock);

	if (rv != 0) {
		nng_fatal("nng_socket", rv);
	}

	for (i = 0; i < PARALLEL; i++) {
		works[i] = alloc_work(sock, sub_cb);
	}

	if ((rv = nng_dialer_create(&dialer, sock, url)) != 0) {
		nng_fatal("nng_dialer_create", rv);
	}

	if (opt->tls.enable) {
		if ((rv = init_dialer_tls(dialer, opt->tls.cacert,
		              opt->tls.cert, opt->tls.key,
		              opt->tls.keypass) != 0)) {
			nng_fatal("init_dialer_tls", rv);
		}
	}

	opt_flag = SUB;
	sub_opt  = opt;

	// Mqtt connect message
	nng_msg *msg;
	nng_mqtt_msg_alloc(&msg, 0);
	nng_mqtt_msg_set_packet_type(msg, NNG_MQTT_CONNECT);
	nng_mqtt_msg_set_connect_proto_version(msg, opt->version);
	nng_mqtt_msg_set_connect_keep_alive(msg, opt->keepalive);
	nng_mqtt_msg_set_connect_clean_session(msg, opt->clean);

	nng_mqtt_set_connect_cb(sock, connect_cb, &sock);
	nng_mqtt_set_disconnect_cb(sock, disconnect_cb, NULL);

	if (opt->username) {
		nng_mqtt_msg_set_connect_user_name(msg, opt->username);
	}

	if (opt->password) {
		nng_mqtt_msg_set_connect_password(msg, opt->password);
	}

	nng_dialer_set_ptr(dialer, NNG_OPT_MQTT_CONNMSG, msg);
	nng_dialer_start(dialer, NNG_FLAG_NONBLOCK);
	works[0]->msg = msg;

	// printf("dialer start after\n");
	for (i = 0; i < PARALLEL; i++) {
		nng_atomic_set(statistics.index_cnt, i);
		sub_cb(works[i]);
	}

	return 0;
}

int
nnb_publish(nnb_pub_opt *opt)
{
	if (opt == NULL) {
		fprintf(stderr, "Connection parameters init failed!\n");
	}

	char         url[255];
	nng_socket   sock;
	nng_dialer   dialer;
	struct work *w;
	int          i;
	int          rv;

	if (opt->tls.enable) {
		sprintf(url, "tls+mqtt-tcp://%s:%d", opt->host, opt->port);
	} else {
		sprintf(url, "mqtt-tcp://%s:%d", opt->host, opt->port);
	}

	rv = opt->version == 5 ? nng_mqttv5_client_open(&sock)
	                       : nng_mqtt_client_open(&sock);

	if (rv != 0) {
		nng_fatal("nng_socket", rv);
	}

	w = alloc_work(sock, pub_cb);

	if ((rv = nng_dialer_create(&dialer, sock, url)) != 0) {
		nng_fatal("nng_dialer_create", rv);
	}

	if (opt->tls.enable) {
		if ((rv = init_dialer_tls(dialer, opt->tls.cacert,
		              opt->tls.cert, opt->tls.key,
		              opt->tls.keypass) != 0)) {
			nng_fatal("init_dialer_tls", rv);
		}
	}

	opt_flag = PUB;
	pub_opt  = opt;

	// Mqtt connect message
	nng_msg *msg;
	nng_mqtt_msg_alloc(&msg, 0);
	nng_mqtt_msg_set_packet_type(msg, NNG_MQTT_CONNECT);
	nng_mqtt_msg_set_connect_proto_version(msg, opt->version);
	nng_mqtt_msg_set_connect_keep_alive(msg, opt->keepalive);
	nng_mqtt_msg_set_connect_clean_session(msg, opt->clean);

	nng_mqtt_set_connect_cb(sock, connect_cb, &sock);
	nng_mqtt_set_disconnect_cb(sock, disconnect_cb, NULL);

	if (opt->username) {
		nng_mqtt_msg_set_connect_user_name(msg, opt->username);
	}
	if (opt->password) {
		nng_mqtt_msg_set_connect_password(msg, opt->password);
	}

	nng_msg_dup(&w->msg, msg);
	nng_dialer_set_ptr(dialer, NNG_OPT_MQTT_CONNMSG, msg);
	nng_dialer_start(dialer, NNG_FLAG_NONBLOCK);

	pub_cb(w);

	return 0;
}

int
bench_dflt(int argc, char **argv)
{
	fprintf(stderr,
	    "Usage: nanomq_cli bench { pub | sub | conn } [--help]\n");
	return 0;
}

int
bench_start(int argc, char **argv)
{
	if (argc < 3) {
		bench_dflt(argc, argv);
		exit(EXIT_FAILURE);
	}
	bench_count_init(&statistics);
	nnb_pub_opt * p_opt;
	nnb_sub_opt * s_opt;
	nnb_conn_opt *c_opt;
	if (!strcmp(argv[2], "pub")) {
		p_opt = nnb_pub_opt_init(argc, argv);
		if (0 == p_opt->limit) {
			nng_atomic_set(statistics.send_limit, INT_MAX);
		} else {
			nng_atomic_set(statistics.send_limit, p_opt->limit);
		}
		for (int i = 0; i < p_opt->count; i++) {
			nnb_publish(p_opt);
			nng_msleep(p_opt->interval);
		}
	} else if (!strcmp(argv[2], "sub")) {
		s_opt= nnb_sub_opt_init(argc, argv);
		for (int i = 0; i < s_opt->count; i++) {
			nnb_subscribe(s_opt);
			nng_msleep(s_opt->interval);
		}
	} else if (!strcmp(argv[2], "conn")) {
		c_opt = nnb_conn_opt_init(argc, argv);
		for (int i = 0; i < c_opt->count; i++) {
			nnb_connect(c_opt);
			nng_msleep(c_opt->interval);
		}
	} else {
		bench_dflt(argc, argv);
		exit(EXIT_FAILURE);
	}

	for (;;) {
		nng_msleep(1000); // neither pause() nor sleep() portable
		switch (opt_flag) {
		case SUB:;
			int c = nng_atomic_get(statistics.recv_cnt);
			int l =
			    nng_atomic_get(statistics.last_recv_cnt);
			nng_atomic_set(statistics.last_recv_cnt, c);
			if (c != l) {
				printf("recv: total=%d, "
				       "rate=%d(msg/sec)\n",
				    c, c - l);
			}
			break;
		case PUB:;
			c = nng_atomic_get(statistics.send_cnt);
			l = nng_atomic_get(statistics.last_send_cnt);
			nng_atomic_set(statistics.last_send_cnt, c);
			if (c != l) {
				printf("sent: total=%d, "
				       "rate=%d(msg/sec)\n",
				    c - pub_opt->count, c - l);
			}
			break;
		default:
			break;
		}
	}

	switch (opt_flag)
	{
	case PUB:
		nnb_pub_opt_destory(p_opt);
		break;

	case SUB:
		nnb_sub_opt_destory(s_opt);
		break;

	case CONN:
		nnb_conn_opt_destory(c_opt);
		break;
	
	default:
		break;
	}

	return 0;
}

#endif