#include "include/bridge.h"
#include "nng/mqtt/mqtt_client.h"
#include "nng/mqtt/mqtt_quic.h"
#include "nng/nng.h"
#include "nng/protocol/mqtt/mqtt.h"
#include "nng/supplemental/nanolib/log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "include/nanomq.h"

#ifdef NNG_SUPP_TLS
#include <nng/supplemental/tls/tls.h>

static int  init_dialer_tls(nng_dialer d, const char *cacert, const char *cert,
     const char *key, const char *pass);
#endif

static int session_is_kept_tcp  = 0;
static int session_is_kept_quic = 0;

static void
fatal(const char *func, int rv)
{
	fprintf(stderr, "%s: %s\n", func, nng_strerror(rv));
}

#define nng_fatal(func, rv) fatal(func, rv)

static int
apply_sqlite_config(
    nng_socket *sock, conf_bridge_node *config, const char *db_name)
{
#if defined(NNG_SUPP_SQLITE)
	int rv;
	// create sqlite option
	nng_mqtt_sqlite_option *opt;
	if ((rv = nng_mqtt_alloc_sqlite_opt(&opt)) != 0) {
		fatal("nng_mqtt_alloc_sqlite_opt", rv);
	}

	nng_mqtt_set_sqlite_conf(opt, config);
	// init sqlite db
	nng_mqtt_sqlite_db_init(opt, db_name);

	// set sqlite option pointer to socket
	return nng_socket_set_ptr(*sock, NNG_OPT_MQTT_SQLITE, opt);
#else
	return (0);
#endif
}

nng_msg *
bridge_publish_msg(const char *topic, uint8_t *payload, uint32_t len, bool dup,
    uint8_t qos, bool retain, property *props)
{
	int rv;

	// create a PUBLISH message
	nng_msg *pubmsg;
	nng_mqtt_msg_alloc(&pubmsg, 0);
	nng_mqtt_msg_set_packet_type(pubmsg, NNG_MQTT_PUBLISH);
	nng_mqtt_msg_set_publish_dup(pubmsg, dup);
	nng_mqtt_msg_set_publish_qos(pubmsg, qos);
	nng_mqtt_msg_set_publish_retain(pubmsg, retain);
	nng_mqtt_msg_set_publish_payload(pubmsg, payload, len);
	nng_mqtt_msg_set_publish_topic(pubmsg, topic);
	if (props) {
		nng_mqtt_msg_set_publish_property(pubmsg, props);
	}
	log_debug("publish to '%s'", topic);

	return pubmsg;
}

static void
send_callback(void *arg)
{
	nng_mqtt_client *client = (nng_mqtt_client *) arg;
	nng_aio *        aio    = client->send_aio;
	nng_msg *        msg    = nng_aio_get_msg(aio);
	uint32_t         count;
	uint8_t *        code;
	uint8_t          type;

	if (msg == NULL || nng_aio_result(aio) != 0)
		return;
	type = nng_msg_get_type(msg);
	if (type == CMD_SUBACK) {
		code = nng_mqtt_msg_get_suback_return_codes(msg, &count);
		log_info("bridge: suback return code %d \n", *(code));
		log_info("bridge: subscribe result %d \n", nng_aio_result(aio));
		nng_msg_free(msg);
	} else if(type == CMD_CONNECT) {
		log_debug("bridge connect msg send complete");
	}
	// nng_mqtt_client_free(client, true);
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
	log_warn("bridge client disconnected! RC [%d] \n", reason);
}

// Connack message callback function
static void
bridge_connect_cb(nng_pipe p, nng_pipe_ev ev, void *arg)
{
	// Connected succeed
	bridge_param *param  = arg;
	int           reason = 0;
	// get connect reason
	nng_pipe_get_int(p, NNG_OPT_MQTT_CONNECT_REASON, &reason);
	// get property for MQTT V5
	// property *prop;
	// nng_pipe_get_ptr(p, NNG_OPT_MQTT_CONNECT_PROPERTY, &prop);
	log_info("Bridge client connected! RC [%d]", reason);

	// Session is saved in mqtt broker
	if (session_is_kept_tcp == 1)
		return;

	/* MQTT V5 SUBSCRIBE */
	if (reason == 0 && param->config->sub_count > 0) {
		nng_mqtt_topic_qos *topic_qos =
		    nng_mqtt_topic_qos_array_create(param->config->sub_count);
		for (size_t i = 0; i < param->config->sub_count; i++) {
			nng_mqtt_topic_qos_array_set(topic_qos, i,
			    param->config->sub_list[i].topic,
			    param->config->sub_list[i].qos);
			log_info("Bridge client subscribed topic (q%d)%s.",
			    param->config->sub_list[i].qos,
			    param->config->sub_list[i].topic);
		}
		nng_mqtt_client *client = param->client;
		// Property?
		nng_mqtt_subscribe_async(
		    client, topic_qos, param->config->sub_count, NULL);
		nng_mqtt_topic_qos_array_free(
		    topic_qos, param->config->sub_count);
	}

	if (param->config->clean_start == false)
		session_is_kept_tcp = 1;
}

static int
bridge_tcp_client(nng_socket *sock, conf *config, conf_bridge_node *node)
{
	int           rv;
	nng_dialer    dialer;
	bridge_param *bridge_arg;

	if (node->proto_ver == MQTT_PROTOCOL_VERSION_v5) {
		if ((rv = nng_mqttv5_client_open(sock)) != 0) {
			fatal("nng_mqttv5_client_open", rv);
			return rv;
		}
	} else {
		if ((rv = nng_mqtt_client_open(sock)) != 0) {
			fatal("nng_mqtt_client_open", rv);
			return rv;
		}
	}

	apply_sqlite_config(sock, node, "mqtt_client.db");

	if ((rv = nng_dialer_create(&dialer, *sock, node->address))) {
		fatal("nng_dialer_create", rv);
		return rv;
	}

#ifdef NNG_SUPP_TLS
	if (node->tls.enable) {
		if ((rv = init_dialer_tls(dialer, node->tls.ca, node->tls.cert,
		         node->tls.key, node->tls.key_password)) != 0) {
			nng_fatal("init_dialer_tls", rv);
		}
	}
#endif



	// create a CONNECT message
	/* CONNECT */
	nng_msg *connmsg;
	nng_mqtt_msg_alloc(&connmsg, 0);
	nng_mqtt_msg_set_packet_type(connmsg, NNG_MQTT_CONNECT);
	nng_mqtt_msg_set_connect_keep_alive(connmsg, node->keepalive);
	nng_mqtt_msg_set_connect_proto_version(connmsg, node->proto_ver);
	nng_mqtt_msg_set_connect_clean_session(connmsg, node->clean_start);
	if (node->clientid) {
		nng_mqtt_msg_set_connect_client_id(connmsg, node->clientid);
	}
	if (node->username) {
		nng_mqtt_msg_set_connect_user_name(connmsg, node->username);
	}
	if (node->password) {
		nng_mqtt_msg_set_connect_password(connmsg, node->password);
	}

	bridge_arg         = (bridge_param *) nng_alloc(sizeof(bridge_param));
	bridge_arg->config = node;
	bridge_arg->sock   = sock;
	bridge_arg->client = nng_mqtt_client_alloc(*sock, send_callback, true);

	node->sock         = (void *) sock;

	// TCP bridge does not support hot update of connmsg
	nng_dialer_set_ptr(dialer, NNG_OPT_MQTT_CONNMSG, connmsg);
	nng_socket_set_ptr(*sock, NNG_OPT_MQTT_CONNMSG, connmsg);
	nng_mqtt_set_connect_cb(*sock, bridge_connect_cb, bridge_arg);
	nng_mqtt_set_disconnect_cb(*sock, disconnect_cb, connmsg);

	nng_dialer_start(dialer, NNG_FLAG_NONBLOCK);

	return 0;
}

#if defined(SUPP_QUIC)

// Disconnect message callback function
static int
quic_disconnect_cb(void *rmsg, void *arg)
{
	int reason = 0;
	if (!rmsg)
		return 0;
	// get connect reason
	reason = nng_mqtt_msg_get_connack_return_code(rmsg);
	// property *prop;
	// nng_pipe_get_ptr(p, NNG_OPT_MQTT_DISCONNECT_PROPERTY, &prop);
	log_debug("quic bridge client disconnected! RC [%d] \n", reason);
	nng_msg_free(rmsg);
	return 0;
}

// Connack message callback function
static int
bridge_quic_connect_cb(void *rmsg, void *arg)
{
	// Connected succeed
	bridge_param *param  = arg;
	nng_msg *msg = rmsg;
	int           reason = 0;
	// get connect reason
	reason = nng_mqtt_msg_get_connack_return_code(msg);
	// get property for MQTT V5
	// property *prop;
	// nng_pipe_get_ptr(p, NNG_OPT_MQTT_CONNECT_PROPERTY, &prop);
	log_info("Quic bridge client connected! RC [%d]", reason);
	nng_msg_free(msg);

	// Session is saved in mqtt broker
	if (session_is_kept_quic == 1)
		return 0;

	/* MQTT V5 SUBSCRIBE */
	if (reason == 0 && param->config->sub_count > 0) {
		nng_mqtt_topic_qos *topic_qos =
		    nng_mqtt_topic_qos_array_create(param->config->sub_count);
		for (size_t i = 0; i < param->config->sub_count; i++) {
			nng_mqtt_topic_qos_array_set(topic_qos, i,
			    param->config->sub_list[i].topic,
			    param->config->sub_list[i].qos);
			log_info("Quic bridge client subscribed topic (q%d)%s.",
			    param->config->sub_list[i].qos,
			    param->config->sub_list[i].topic);
		}

		nng_mqtt_client *client = param->client;
		// TODO support MQTT V5
		nng_mqtt_subscribe_async(
		    client, topic_qos, param->config->sub_count, NULL);
		nng_mqtt_topic_qos_array_free(
		    topic_qos, param->config->sub_count);
	}

	if (param->config->clean_start == false)
		session_is_kept_quic = 1;
	return 0;
}


static int
bridge_quic_client(nng_socket *sock, conf *config, conf_bridge_node *node)
{
	int           rv;
	nng_dialer    dialer;
	bridge_param *bridge_arg;
	log_debug("Quic bridge service start.\n");

	// keepalive here is for QUIC only
	if ((rv = nng_mqtt_quic_open_conf(sock, node->address, node)) != 0) {
		fatal("nng_mqtt_quic_client_open", rv);
		return rv;
	}
	// mqtt v5 protocol
	apply_sqlite_config(sock, node, "mqtt_quic_client.db");

	bridge_arg         = (bridge_param *) nng_alloc(sizeof(bridge_param));
	bridge_arg->config = node;
	bridge_arg->sock   = sock;
	bridge_arg->client = nng_mqtt_client_alloc(*sock, send_callback, true);

	node->sock = (void *) sock;

	if (0 != nng_mqtt_quic_set_connect_cb(sock, bridge_quic_connect_cb, (void *)bridge_arg) ||
	    0 != nng_mqtt_quic_set_disconnect_cb(sock, quic_disconnect_cb, (void *)bridge_arg)) {
	    //0 != nng_mqtt_quic_set_msg_recv_cb(sock, msg_recv_cb, (void *)arg) ||
	    //0 != nng_mqtt_quic_set_msg_send_cb(sock, msg_send_cb, (void *)arg)) {
		log_debug("error in quic client cb set.");
		return -1;
	}

	// create a CONNECT message
	/* CONNECT */
	nng_msg *connmsg;
	nng_mqtt_msg_alloc(&connmsg, 0);
	nng_mqtt_msg_set_packet_type(connmsg, NNG_MQTT_CONNECT);
	nng_mqtt_msg_set_connect_keep_alive(connmsg, node->keepalive);
	nng_mqtt_msg_set_connect_proto_version(connmsg, node->proto_ver);
	nng_mqtt_msg_set_connect_clean_session(connmsg, node->clean_start);
	if (node->clientid) {
		nng_mqtt_msg_set_connect_client_id(connmsg, node->clientid);
	}
	if (node->username) {
		nng_mqtt_msg_set_connect_user_name(connmsg, node->username);
	}
	if (node->password) {
		nng_mqtt_msg_set_connect_password(connmsg, node->password);
	}

	nng_aio_set_msg(bridge_arg->client->send_aio, connmsg);
	nng_send_aio(*sock, bridge_arg->client->send_aio);

	return 0;
}

#endif

int
bridge_client(nng_socket *sock, conf *config, conf_bridge_node *node)
{
	char *quic_scheme = "mqtt-quic";
	char *tcp_scheme = "mqtt-tcp";
	char *tls_scheme = "tls+mqtt-tcp";
	if (0 == strncmp(node->address, tcp_scheme, 8) || 0 == strncmp(node->address, tls_scheme, 12)) {
		bridge_tcp_client(sock, config, node);
#if defined(SUPP_QUIC)
	} else if (0 == strncmp(node->address, quic_scheme, 9)) {
		bridge_quic_client(sock, config, node);
#endif
	} else {
		printf("Unsupported bridge protocol.\n");
	}
	return 0;
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