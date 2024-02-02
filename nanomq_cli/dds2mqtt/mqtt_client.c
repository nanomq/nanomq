// Author: wangha <wanghamax at gmail dot com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

//
// This is a simple wrap for nanosdk to help send and receive mqtt msgs
// for dds2mqtt.
//
#if defined(SUPP_DDS_PROXY)

#include <assert.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "idl_convert.h"

// #include "dds_mqtt_type_conversion.h"
#include "mqtt_client.h"
#include "vector.h"
#include "dds_client.h"
#include "dds_utils.h"

#include <nng/mqtt/mqtt_client.h>
#include <nng/nng.h>
#include <nng/supplemental/util/platform.h>
#include "nng/supplemental/nanolib/utils.h"

#ifdef NNG_SUPP_TLS
#include <nng/supplemental/tls/tls.h>
static int init_dialer_tls(nng_dialer d, const char *cacert, const char *cert,
    const char *key, const char *pass);
#endif

static int recv_cnt = 0;
static int sent_cnt = 0;
static int forward2dds_cnt = 0;

handle *
mk_handle(int type, void *data, int len, char *topic)
{
	handle *hd = malloc(sizeof(handle));
	if (hd == NULL)
		return NULL;
	hd->data  = data;
	hd->type  = type;
	hd->len   = len;
	hd->topic = topic;

	return hd;
}

dds_gateway_topic *
find_dds_topic(dds_gateway_conf *conf, const char *mqtttopic)
{
	dds_gateway_topic **tl = conf->forward.mqtt2dds;
	for (size_t i=0; i<conf->forward.mqtt2dds_sz; ++i) {
		if (0 == strcmp(mqtttopic, tl[i]->from))
			return tl[i];
	}
	return NULL;
}

dds_gateway_topic *
find_mqtt_topic(dds_gateway_conf *conf, const char *ddstopic)
{
	dds_gateway_topic **tl = conf->forward.dds2mqtt;
	for (size_t i=0; i<conf->forward.dds2mqtt_sz; ++i) {
		if (0 == strcmp(ddstopic, tl[i]->from))
			return tl[i];
	}
	return NULL;
}

static void
send_callback (nng_mqtt_client *client, nng_msg *msg, void *arg) {
	nng_aio *        aio    = client->send_aio;
	uint32_t         count;
	uint8_t *        code;
	uint8_t          type;

	if (msg == NULL)
		return;
	switch (nng_mqtt_msg_get_packet_type(msg)) {
	case NNG_MQTT_SUBACK:
		code = nng_mqtt_msg_get_suback_return_codes(
		    msg, &count);
		log_dds("[MQTT] SUBACK reason codes are: ");
		for (int i = 0; i < count; ++i)
			log_dds("%d ", code[i]);
		break;
	case NNG_MQTT_UNSUBACK:
		code = nng_mqtt_msg_get_unsuback_return_codes(
		    msg, &count);
		log_dds("[MQTT] UNSUBACK reason codes are");
		for (int i = 0; i < count; ++i)
			log_dds("%d ", code[i]);
		break;
	case NNG_MQTT_PUBACK:
		log_dds("Received a PUBACK");
		break;
	default:
		log_dds("Sending in async way is done.");
		break;
	}
	log_dds("[MQTT] aio mqtt result %d", nng_aio_result(aio));
	nng_msg_free(msg);
}

static void
disconnect_cb(nng_pipe p, nng_pipe_ev ev, void *arg)
{
	int reason = 0;
	// get connect reason
	nng_pipe_get_int(p, NNG_OPT_MQTT_DISCONNECT_REASON, &reason);
	// property *prop;
	// nng_pipe_get_ptr(p, NNG_OPT_MQTT_DISCONNECT_PROPERTY, &prop);
	// nng_socket_get?
	log_dds("[MQTT] %d disconnected!", p.id);
}

static void
connect_cb(nng_pipe p, nng_pipe_ev ev, void *arg)
{
	int reason;
	// get connect reason
	nng_pipe_get_int(p, NNG_OPT_MQTT_CONNECT_REASON, &reason);
	// get property for MQTT V5
	// property *prop;
	// nng_pipe_get_ptr(p, NNG_OPT_MQTT_CONNECT_PROPERTY, &prop);
	log_dds("[MQTT] %d connected!\n", p.id);

	mqtt_cli *cli = arg;
	mqtt_subscribe(cli);
}

// Connect to the given address.
static int
client_connect(
    mqtt_cli *cli, nng_dialer *dialer, bool verbose)
{

	int rv;

	nng_socket       *sock      = &cli->sock;
	dds_gateway_conf *config    = cli->config;
	dds_gateway_mqtt *mqtt_conf = &config->mqtt;

	if (mqtt_conf->proto_ver == 5) {
		if ((rv = nng_mqttv5_client_open(sock)) != 0) {
			log_dds("nng_socket: %s\n", nng_strerror(rv));
		}
	} else {
		if ((rv = nng_mqtt_client_open(sock)) != 0) {
			log_dds("nng_socket: %s\n", nng_strerror(rv));
		}
	}

	mqtt_conf->sock = sock;

	if ((rv = nng_dialer_create(dialer, *sock, mqtt_conf->address)) != 0) {
		log_dds("nng_dialer_create: %s\n", nng_strerror(rv));
	}

	cli->client = nng_mqtt_client_alloc(cli->sock, &send_callback, true);

	// create a CONNECT message
	/* CONNECT */
	nng_msg *connmsg;
	nng_mqtt_msg_alloc(&connmsg, 0);
	nng_mqtt_msg_set_packet_type(connmsg, NNG_MQTT_CONNECT);
	nng_mqtt_msg_set_connect_proto_version(connmsg, mqtt_conf->proto_ver);
	nng_mqtt_msg_set_connect_keep_alive(connmsg, 60);
	nng_mqtt_msg_set_connect_user_name(connmsg, mqtt_conf->username);
	nng_mqtt_msg_set_connect_password(connmsg, mqtt_conf->password);
	nng_mqtt_msg_set_connect_will_msg(
	    connmsg, (uint8_t *) "bye-bye", strlen("bye-bye"));
	nng_mqtt_msg_set_connect_will_topic(connmsg, "will_topic");
	nng_mqtt_msg_set_connect_clean_session(connmsg, mqtt_conf->clean_start);

	nng_mqtt_set_connect_cb(*sock, connect_cb, cli);
	nng_mqtt_set_disconnect_cb(*sock, disconnect_cb, connmsg);

	uint8_t buff[1024] = { 0 };

	if (verbose) {
		nng_mqtt_msg_dump(connmsg, buff, sizeof(buff), true);
		log_dds("%s\n", buff);
	}

#ifdef NNG_SUPP_TLS

	conf_tls tls = mqtt_conf->tls;
	if (tls.enable) {
		if ((rv = init_dialer_tls(*dialer, tls.ca, tls.cert,
		         tls.key, tls.key_password)) != 0) {
			fatal("init_dialer_tls", rv);
		}
	}
#endif

	log_dds("[MQTT] Connecting to server ...");
	nng_dialer_set_ptr(*dialer, NNG_OPT_MQTT_CONNMSG, connmsg);
	if (0 != (rv = nng_dialer_start(*dialer, NNG_FLAG_ALLOC))) {
		log_dds("nng_dialer_start: %s(%d)\n", nng_strerror(rv), rv);
		exit(1);
	}

	return (0);
}

// Publish a message to the given topic and with the given QoS.
static int
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

	if (verbose) {
		uint8_t print[1024] = { 0 };
		nng_mqtt_msg_dump(pubmsg, print, 1024, true);
		log_dds("%s", print);
	}

	if ((rv = nng_sendmsg(sock, pubmsg, NNG_FLAG_NONBLOCK)) != 0) {
		log_dds("nng_sendmsg: %s\n", nng_strerror(rv));
	}

	return rv;
}

static pthread_t recvthr;
static nftp_vec *rmsgq;
static pthread_mutex_t rmsgq_mtx;

static int
client_recv2(mqtt_cli *cli, nng_msg **msgp)
{
	int      rv;
	nng_msg *msg;
	if ((rv = nng_recvmsg(cli->sock, &msg, NNG_FLAG_NONBLOCK)) != 0) {
		log_dds("[MQTT] Error in nng_recvmsg %d.", rv);
		return -1;
	}

	// we should only receive publish messages
	nng_mqtt_packet_type type = nng_mqtt_msg_get_packet_type(msg);

	if (type == NNG_MQTT_CONNACK) {
		return -2;
	}

	if (type != NNG_MQTT_PUBLISH) {
		log_dds("[MQTT] Received a %x type msg. Skip.", type);
		return -3;
	}

	uint32_t topicsz;
	const char * topic = nng_mqtt_msg_get_publish_topic(msg, &topicsz);
	log_dds("[MQTT] Received from '%.*s', counter %d", topicsz, topic, ++recv_cnt);

	*msgp = msg;
	return 0;
}

static void *
mqtt_recv_loop(void *arg)
{
	mqtt_cli      *cli = arg;
	nng_msg       *msg;

	while (cli->running) {
		msg = NULL;
		if (0 != client_recv2(cli, &msg))
			continue;

		uint32_t topicsz;
		const char *topic = nng_mqtt_msg_get_publish_topic(msg, &topicsz);
		char *srctopic = strndup(topic, topicsz);

		handle *hd;
		hd = mk_handle(HANDLE_TO_DDS, msg, 0, srctopic);

		pthread_mutex_lock(&cli->mtx);
		// watermark log
		if (nftp_vec_len(cli->handleq) * 4 == nftp_vec_cap(cli->handleq)) {
			log_dds("WARNING 1 / 4 of the queue from MQTT to DDS is used.");
		} else if (nftp_vec_len(cli->handleq) * 2 == nftp_vec_cap(cli->handleq)) {
			log_dds("WARNING 1 / 2 of the queue from MQTT to DDS is used.");
		} else if (nftp_vec_len(cli->handleq) == nftp_vec_cap(cli->handleq)) {
			log_dds("WARNING All of the queue from MQTT to DDS is used. Drop msg.");
		}

		nftp_vec_append(cli->handleq, (void *) hd);
		pthread_cond_signal(&cli->cv);
		pthread_mutex_unlock(&cli->mtx);
	}

	return NULL;
}

static void *
mqtt_loop(void *arg)
{
	mqtt_cli      *cli = arg;
	handle        *hd  = NULL;
	nng_msg       *msg;
	void          *ddsmsg;
	fixed_mqtt_msg mqttmsg;
	int            rv;
	dds_cli       *ddscli = cli->ddscli;

	dds_gateway_conf *conf = cli->config;

	while (cli->running) {
		// If handle queue is not empty. Handle it first.
		// Or we need to receive msgs from nng in a NONBLOCK way and
		// put it to the handle queue. Wait cv when handle queue is
		// empty.
		hd = NULL;

		pthread_mutex_lock(&cli->mtx);
		while (nftp_vec_len(cli->handleq) == 0)
			pthread_cond_wait(&cli->cv, &cli->mtx);
		if (nftp_vec_len(cli->handleq))
			nftp_vec_pop(cli->handleq, (void **) &hd, NFTP_HEAD);
		pthread_mutex_unlock(&cli->mtx);

		if (hd)
			goto work;

		continue;

	work:
		switch (hd->type) {
		case HANDLE_TO_DDS:
			// Put to DDSClient's handle queue
			pthread_mutex_lock(&ddscli->mtx);
			nftp_vec_append(ddscli->handleq, (void *) hd);
			pthread_cond_signal(&ddscli->cv);
			pthread_mutex_unlock(&ddscli->mtx);

			log_dds("[MQTT] forward msg to dds, counter %d", ++forward2dds_cnt);
			break;
		case HANDLE_TO_MQTT:
			// Translate DDS msg to MQTT format
			ddsmsg = hd->data;

			dds_handler_set *dds_handler;
			dds_gateway_topic *dt = find_mqtt_topic(conf, hd->topic);

			if (dt) {
				dds_handler = dds_get_handler(dt->struct_name);
				cJSON *json = dds_handler->dds2mqtt(ddsmsg);
				dds_handler->free(ddsmsg, DDS_FREE_ALL);

				mqttmsg.payload = cJSON_PrintUnformatted(json);
				mqttmsg.len     = strlen(mqttmsg.payload);
				cJSON_Delete(json);

				log_dds("[MQTT] Sent topic %s, struct %s, cnt%d", dt->to,
					dt->struct_name, ++sent_cnt);
				mqtt_publish(cli, dt->to, 0,
				    (uint8_t *)mqttmsg.payload, mqttmsg.len);
				nng_free(mqttmsg.payload, mqttmsg.len);
				mqttmsg.len = 0;
			}

			free(hd->topic);
			free(hd);
			break;
		default:
			log_dds("Unsupported handle type.\n");
			break;
		}
	}

	return NULL;
}

int
mqtt_connect(mqtt_cli *cli, void *dc, dds_gateway_conf *config)
{
	bool       verbose = 0;
	nng_dialer dialer;
	dds_cli *  ddscli = dc;

	cli->config = config;

	client_connect(cli, &dialer, verbose);

	// Start mqtt thread
	cli->running = 1;

	nftp_vec_alloc(&cli->handleq);
	pthread_mutex_init(&cli->mtx, NULL);
	pthread_cond_init(&cli->cv, NULL);

	cli->ddscli = ddscli;

	// XXX Create a temparary thread to recv mqtt msg
	nftp_vec_alloc(&rmsgq);
	pthread_mutex_init(&rmsgq_mtx, NULL);
	pthread_create(&recvthr, NULL, mqtt_recv_loop, (void *) cli);

	// Create a thread to send / recv mqtt msg
	pthread_create(&cli->thr, NULL, mqtt_loop, (void *) cli);

	return 0;
}

int
mqtt_disconnect(mqtt_cli *cli)
{
	cli->running = 0;

	if (cli->handleq)
		nftp_vec_free(cli->handleq);
	pthread_mutex_destroy(&cli->mtx);
	pthread_cond_destroy(&cli->cv);

	// XXX Remove the temparary rmsgq and its mtx
	nftp_vec_free(rmsgq);
	pthread_mutex_destroy(&rmsgq_mtx);
	return 0;
}

int
mqtt_subscribe(mqtt_cli *cli)
{
	dds_gateway_conf *config = cli->config;

	nng_mqtt_topic_qos subscriptions[config->forward.mqtt2dds_sz];

	for (size_t i=0; i<config->forward.mqtt2dds_sz; ++i) {
		subscriptions[i].qos = 0;
		subscriptions[i].topic.buf = config->forward.mqtt2dds[i]->from;
		subscriptions[i].topic.length = strlen(config->forward.mqtt2dds[i]->from);
	}

	return nng_mqtt_subscribe_async(cli->client, subscriptions, config->forward.mqtt2dds_sz, NULL);
}

int
mqtt_publish(
    mqtt_cli *cli, const char *topic, uint8_t qos, uint8_t *data, int len)
{
	return client_publish(cli->sock, topic, data, len, qos, 0);
}

int
mqtt_recvmsg(mqtt_cli *cli, nng_msg **msgp)
{
	return 0;
}

/*
static void
sub_callback(void *arg) {
        nng_mqtt_client *client = (nng_mqtt_client *) arg;
        nng_aio *aio = client->sub_aio;
        nng_msg *msg = nng_aio_get_msg(aio);
        uint32_t count;
        reason_code *code;
        code = (reason_code *)nng_mqtt_msg_get_suback_return_codes(msg,
&count); printf("aio mqtt result %d \n", nng_aio_result(aio));
        // printf("suback %d \n", *code);
        nng_msg_free(msg);
}

static void
unsub_callback(void *arg) {
        nng_mqtt_client *client = (nng_mqtt_client *) arg;
        nng_aio *aio = client->unsub_aio;
        nng_msg *msg = nng_aio_get_msg(aio);
        uint32_t count;
        reason_code *code;
        // code = (reason_code *)nng_mqtt_msg_get_suback_return_codes(msg,
&count); printf("aio mqtt result %d \n", nng_aio_result(aio));
        // printf("suback %d \n", *code);
        nng_msg_free(msg);
}
*/


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





#endif
