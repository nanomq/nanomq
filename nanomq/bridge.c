#include "include/bridge.h"
#include "nng/mqtt/mqtt_client.h"
#include "nng/mqtt/mqtt_quic.h"
#include "nng/nng.h"
#include "nng/protocol/mqtt/mqtt.h"
#include "nng/supplemental/nanolib/log.h"
#include "nng/supplemental/util/platform.h"
#include "nng/supplemental/nanolib/utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "include/nanomq.h"

#ifdef NNG_SUPP_TLS
#include "nng/supplemental/tls/tls.h"
static int init_dialer_tls(nng_dialer d, const char *cacert, const char *cert,
    const char *key, const char *pass);
#endif

static property *sub_property(conf_bridge_sub_properties *conf_prop);
static property *conn_property(conf_bridge_conn_properties *conf_prop);

static nng_thread *hybridger_thr;

static int
apply_sqlite_config(
    nng_socket *sock, conf_bridge_node *config, const char *db_name)
{
#if defined(NNG_SUPP_SQLITE)
	int rv;
	// create sqlite option
	nng_mqtt_sqlite_option *opt;
	if ((rv = nng_mqtt_alloc_sqlite_opt(&opt)) != 0) {
		nng_fatal("nng_mqtt_alloc_sqlite_opt", rv);
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

	if (nng_aio_result(aio) != 0) {
		return;
	}

	nng_msg *        msg    = nng_aio_get_msg(aio);
	uint32_t         count;
	uint8_t *        code;
	uint8_t          type;

	if (msg == NULL || nng_aio_result(aio) != 0)
		return;
	type = nng_msg_get_type(msg);
	if (type == CMD_SUBACK) {
		code = nng_mqtt_msg_get_suback_return_codes(msg, &count);
		log_info("bridge: subscribe aio result %d suback code", nng_aio_result(aio), *(code));
		nng_msg_free(msg);
	} else if(type == CMD_CONNECT) {
		log_debug("send bridge connect msg complete");
	}
	if (nng_lmq_get(client->msgq, &msg) == 0) {
		nng_aio_set_msg(client->send_aio, msg);
		nng_send_aio(client->sock, client->send_aio);
	}
	// nng_mqtt_client_free(client, true);
}

// Disconnect message callback function for hyrbrid bridging
static void
hybrid_disconnect_cb(nng_pipe p, nng_pipe_ev ev, void *arg)
{
	int reason = 0;
	// get connect reason
	nng_pipe_get_int(p, NNG_OPT_MQTT_DISCONNECT_REASON, &reason);
	log_warn("bridge client disconnected! RC [%d] \n", reason);
	bridge_param *bridge_arg = arg;

	nng_mtx_lock(bridge_arg->switch_mtx);
	nng_cv_wake1(bridge_arg->switch_cv);
	nng_mtx_unlock(bridge_arg->switch_mtx);
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

	/* MQTT V5 SUBSCRIBE */
	if (reason == 0 && param->config->sub_count > 0) {
		nng_mqtt_topic_qos *topic_qos =
		    nng_mqtt_topic_qos_array_create(param->config->sub_count);
		for (size_t i = 0; i < param->config->sub_count; i++) {
			nng_mqtt_topic_qos_array_set(topic_qos, i,
			    param->config->sub_list[i].topic,
			    param->config->sub_list[i].qos);
			log_info("Bridge client subscribed topic %s (qos %d).",
			    param->config->sub_list[i].topic,
			    param->config->sub_list[i].qos);
		}
		nng_mqtt_client *client = param->client;

		// Property
		property *properties = NULL;
		if (param->config->proto_ver == MQTT_PROTOCOL_VERSION_v5) {
			properties =
			    sub_property(param->config->sub_properties);
		}
		nng_mqtt_subscribe_async(
		    client, topic_qos, param->config->sub_count, properties);
		nng_mqtt_topic_qos_array_free(
		    topic_qos, param->config->sub_count);
	}

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

static property *
sub_property(conf_bridge_sub_properties *conf_prop)
{
	if (conf_prop) {
		property *link_list = mqtt_property_alloc();
		property *prop;

		if (conf_prop->identifier != 0xffffffff) {
			prop = mqtt_property_set_value_varint(
			    SUBSCRIPTION_IDENTIFIER, conf_prop->identifier);
			mqtt_property_append(link_list, prop);
		}

		if (conf_prop->user_property_size > 0 &&
		    conf_prop->user_property) {
			for (size_t i = 0; i < conf_prop->user_property_size;
			     i++) {
				prop = mqtt_property_set_value_strpair(
				    USER_PROPERTY,
				    conf_prop->user_property[i]->key,
				    strlen(conf_prop->user_property[i]->key),
				    conf_prop->user_property[i]->value,
				    strlen(conf_prop->user_property[i]->value),
				    false);
				mqtt_property_append(link_list, prop);
			}
		}
		return link_list;
	}
	return NULL;
}

static property *
conn_property(conf_bridge_conn_properties *conf_prop)
{
	if (conf_prop) {
		property *link_list = mqtt_property_alloc();
		property *prop;
		if (conf_prop->maximum_packet_size != 0) {
			prop = mqtt_property_set_value_u32(MAXIMUM_PACKET_SIZE,
			    conf_prop->maximum_packet_size);
			mqtt_property_append(link_list, prop);
		}
		if (conf_prop->receive_maximum != 65535) {
			prop = mqtt_property_set_value_u16(
			    RECEIVE_MAXIMUM, conf_prop->receive_maximum);
			mqtt_property_append(link_list, prop);
		}
		if (conf_prop->topic_alias_maximum != 0) {
			prop = mqtt_property_set_value_u16(TOPIC_ALIAS_MAXIMUM,
			    conf_prop->topic_alias_maximum);
			mqtt_property_append(link_list, prop);
		}
		if (conf_prop->request_response_info != 0) {
			prop = mqtt_property_set_value_u8(
			    REQUEST_RESPONSE_INFORMATION,
			    conf_prop->request_response_info);
			mqtt_property_append(link_list, prop);
		}
		if (conf_prop->request_problem_info != 1) {
			prop = mqtt_property_set_value_u8(
			    REQUEST_PROBLEM_INFORMATION,
			    conf_prop->request_problem_info);
			mqtt_property_append(link_list, prop);
		}
		if (conf_prop->session_expiry_interval != 0) {
			prop = mqtt_property_set_value_u32(
			    SESSION_EXPIRY_INTERVAL,
			    conf_prop->session_expiry_interval);
			mqtt_property_append(link_list, prop);
		}
		if (conf_prop->user_property_size > 0 &&
		    conf_prop->user_property) {
			for (size_t i = 0; i < conf_prop->user_property_size;
			     i++) {
				prop = mqtt_property_set_value_strpair(
				    USER_PROPERTY,
				    conf_prop->user_property[i]->key,
				    strlen(conf_prop->user_property[i]->key),
				    conf_prop->user_property[i]->value,
				    strlen(conf_prop->user_property[i]->value),
				    false);
				mqtt_property_append(link_list, prop);
			}
		}
		return link_list;
	}
	return NULL;
}

static int
hybrid_bridge_tcp_client(bridge_param *bridge_arg)
{
	int           rv;
	nng_dialer    dialer;

	nng_socket *      sock = bridge_arg->sock;
	conf_bridge_node *node = bridge_arg->config;

	if (node->proto_ver == MQTT_PROTOCOL_VERSION_v5) {
		if ((rv = nng_mqttv5_client_open(sock)) != 0) {
			nng_fatal("nng_mqttv5_client_open", rv);
			return rv;
		}
	} else {
		if ((rv = nng_mqtt_client_open(sock)) != 0) {
			nng_fatal("nng_mqtt_client_open", rv);
			return rv;
		}
	}

	apply_sqlite_config(sock, node, "mqtt_client.db");

	if ((rv = nng_dialer_create(&dialer, *sock, node->address))) {
		nng_fatal("nng_dialer_create", rv);
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

	if (node->proto_ver == MQTT_PROTOCOL_VERSION_v5) {
		property *properties = conn_property(node->conn_properties);
		nng_mqtt_msg_set_connect_property(connmsg, properties);
	}

	bridge_arg->client = nng_mqtt_client_alloc(*sock, send_callback, true);

	node->sock         = (void *) sock;

	// TCP bridge does not support hot update of connmsg
	nng_dialer_set_ptr(dialer, NNG_OPT_MQTT_CONNMSG, connmsg);
	nng_socket_set_ptr(*sock, NNG_OPT_MQTT_CONNMSG, connmsg);
	nng_mqtt_set_connect_cb(*sock, bridge_connect_cb, bridge_arg);
	nng_mqtt_set_disconnect_cb(*sock, disconnect_cb, bridge_arg);

	nng_dialer_start(dialer, NNG_FLAG_NONBLOCK);

	return 0;
}

static int
bridge_tcp_client(nng_socket *sock, conf *config, conf_bridge_node *node)
{
	int           rv;
	nng_dialer    dialer;
	bridge_param *bridge_arg;

	if (node->proto_ver == MQTT_PROTOCOL_VERSION_v5) {
		if ((rv = nng_mqttv5_client_open(sock)) != 0) {
			nng_fatal("nng_mqttv5_client_open", rv);
			return rv;
		}
	} else {
		if ((rv = nng_mqtt_client_open(sock)) != 0) {
			nng_fatal("nng_mqtt_client_open", rv);
			return rv;
		}
	}

	apply_sqlite_config(sock, node, "mqtt_client.db");

	if ((rv = nng_dialer_create(&dialer, *sock, node->address))) {
		nng_fatal("nng_dialer_create", rv);
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

	if (node->proto_ver == MQTT_PROTOCOL_VERSION_v5) {
		property *properties = conn_property(node->conn_properties);
		nng_mqtt_msg_set_connect_property(connmsg, properties);
	}

	bridge_arg = (bridge_param *) nng_alloc(sizeof(bridge_param));
	if (bridge_arg == NULL) {
		log_error("memory error in allocating bridge client");
		return NNG_ENOMEM;
	}
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
hybrid_quic_disconnect_cb(void *rmsg, void *arg)
{
	int reason = 0;
	if (rmsg) {
		// get connect reason
		reason = nng_mqtt_msg_get_connack_return_code(rmsg);
		nng_msg_free(rmsg);
	}
	log_warn("quic bridge client disconnected! RC [%d]", reason);

	// wait 3000ms and ready to reconnect
	nng_msleep(3000);
	bridge_param *bridge_arg = arg;

	nng_mtx_lock(bridge_arg->switch_mtx);
	nng_cv_wake1(bridge_arg->switch_cv);
	nng_mtx_unlock(bridge_arg->switch_mtx);

	return 0;
}


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

static void
quic_ack_cb(void *arg)
{
	int result = 0;

	nng_aio *     aio   = arg;
	bridge_param *param = nng_aio_get_prov_data(aio);
	nng_socket *  sock  = param->sock;
	nng_msg *     msg   = nng_aio_get_msg(aio);
	if ((result = nng_aio_result(aio)) != 0) {
		log_debug("no msg wating!");
		return;
	}
	if (nng_msg_get_type(msg) == CMD_CONNACK) {
		nng_mqtt_client *client = param->client;
		int              reason = 0;
		// get connect reason
		reason = nng_mqtt_msg_get_connack_return_code(msg);
		// get property for MQTT V5
		// property *prop;
		// nng_pipe_get_ptr(p, NNG_OPT_MQTT_CONNECT_PROPERTY, &prop);
		log_info("Quic bridge client connected! RC [%d]", reason);

		if (reason != 0 || param->config->sub_count <= 0)
			return;
		/* MQTT SUBSCRIBE */
		if (param->config->multi_stream) {
			for (size_t i = 0; i < param->config->sub_count; i++) {
				nng_mqtt_topic_qos *topic_qos =
				    nng_mqtt_topic_qos_array_create(1);
				nng_mqtt_topic_qos_array_set(topic_qos, 0,
				    param->config->sub_list[i].topic,
				    param->config->sub_list[i].qos);
				log_info("Quic bridge client subscribe to "
				         "topic (QoS "
				         "%d)%s.",
				    param->config->sub_list[i].qos,
				    param->config->sub_list[i].topic);
				nng_mqtt_subscribe_async(
				    client, topic_qos, 1, NULL);
				nng_mqtt_topic_qos_array_free(topic_qos, 1);
			}
		} else {
			nng_mqtt_topic_qos *topic_qos =
			    nng_mqtt_topic_qos_array_create(
			        param->config->sub_count);
			for (size_t i = 0; i < param->config->sub_count; i++) {
				nng_mqtt_topic_qos_array_set(topic_qos, i,
				    param->config->sub_list[i].topic,
				    param->config->sub_list[i].qos);
				log_info("Quic bridge client subscribed topic "
				         "(q%d)%s.",
				    param->config->sub_list[i].qos,
				    param->config->sub_list[i].topic);
			}
			// TODO support MQTT V5
			nng_mqtt_subscribe_async(
			    client, topic_qos, param->config->sub_count, NULL);
			nng_mqtt_topic_qos_array_free(
			    topic_qos, param->config->sub_count);
		}
	}

	log_debug("ACK msg is recevied in bridging");

	nng_msg_free(msg);
	// To clean the cached msg if any
	nng_recv_aio(*sock, aio);
}

// Connack message callback function
static int
bridge_quic_connect_cb(void *rmsg, void *arg)
{
	// Connected succeed
	bridge_param    *param  = arg;
	nng_msg         *msg    = rmsg;
	nng_mqtt_client *client = param->client;
	int              reason = 0;
	// get connect reason
	reason = nng_mqtt_msg_get_connack_return_code(msg);
	// get property for MQTT V5
	// property *prop;
	// nng_pipe_get_ptr(p, NNG_OPT_MQTT_CONNECT_PROPERTY, &prop);
	log_info("Quic bridge client connected! RC [%d]", reason);
	nng_msg_free(msg);
	return 0;
}


static int
hybrid_bridge_quic_client(bridge_param *bridge_arg)
{
	int           rv;
	nng_dialer    dialer;
	log_info("Quic bridge service start.");

	nng_socket *sock = bridge_arg->sock;
	conf_bridge_node* node = bridge_arg->config;
	node->sock         = (void *) sock;

	// keepalive here is for QUIC only
	if ((rv = nng_mqtt_quic_open_keepalive(sock, node->address, (void *)node)) != 0) {
		nng_fatal("nng_mqtt_quic_client_open", rv);
		return rv;
	}
	// TODO mqtt v5 protocol
	apply_sqlite_config(sock, node, "mqtt_quic_client.db");
	nng_socket_set(*sock, NANO_CONF, node, sizeof(conf_bridge_node));

	bridge_arg->client = nng_mqtt_client_alloc(*sock, send_callback, true);

	if (0 != nng_mqtt_quic_set_connect_cb(sock, bridge_quic_connect_cb, (void *)bridge_arg) ||
	    0 != nng_mqtt_quic_set_disconnect_cb(sock, hybrid_quic_disconnect_cb, (void *)bridge_arg)) {
	    //0 != nng_mqtt_quic_set_msg_recv_cb(sock, msg_recv_cb, (void *)arg) ||
	    //0 != nng_mqtt_quic_set_msg_send_cb(sock, msg_send_cb, (void *)arg)) {
		log_error("error in quic client cb setting.");
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

static int
bridge_quic_client(nng_socket *sock, conf *config, conf_bridge_node *node)
{
	int           rv;
	nng_dialer    dialer;
	bridge_param *bridge_arg;
	log_debug("Quic bridge service start.\n");

	// keepalive here is for QUIC only
	if ((rv = nng_mqtt_quic_open_keepalive(sock, node->address, (void *)node)) != 0) {
		nng_fatal("nng_mqtt_quic_client_open", rv);
		return rv;
	}
	// mqtt v5 protocol
	apply_sqlite_config(sock, node, "mqtt_quic_client.db");

	bridge_arg         = (bridge_param *) nng_alloc(sizeof(bridge_param));
	if (bridge_arg == NULL) {
		log_error("memory error in allocating bridge client");
		return NNG_ENOMEM;
	}
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
	nng_mqtt_quic_ack_callback_set(sock, quic_ack_cb, (void *)bridge_arg);

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

static int
gen_fallback_url(char *url, char *new) {
	int pos_ip = 0;
	int len_ip = 0;
	for (int i=0; i<strlen(url)-1; ++i)
		if (url[i] == '/' && url[i+1] == '/')
			pos_ip = i+2;
	for (int i=pos_ip; i<strlen(url); ++i) {
		if (url[i] == ':')
			break;
		len_ip ++;
	}
	if (len_ip < 2)
		return -1;
	strncpy(new, "mqtt-tcp://", 11);
	strncpy(new+11, url+pos_ip, len_ip);
	strncpy(new+11+len_ip, ":1883", 5);
	return 0;
}


static void
hybridger_cb(void *arg)
{
	const char *quic_scheme = "mqtt-quic";
	const char *tcp_scheme  = "mqtt-tcp";

	bridge_param *bridge_arg = arg;
	conf_bridge_node *node = bridge_arg->config;

	int rv = nng_mtx_alloc(&bridge_arg->switch_mtx);
	if (rv != 0) {
		nng_fatal("nng_mtx_alloc", rv);
		return;
	}
	rv = nng_cv_alloc(&bridge_arg->switch_cv, bridge_arg->switch_mtx);
	if (rv != 0) {
		nng_fatal("nng_cv_alloc", rv);
		return;
	}

	char addr_back[strlen(node->address)+1];
	memset(addr_back, '\0', strlen(node->address)+1);
	if (0 != gen_fallback_url(node->address, addr_back))
		strcpy(addr_back, node->address);
	char * addrs[] = {node->address, addr_back};
	int idx = -1;
	for (;;) {
		// Get next bridge node
		idx = (idx + 1) % 2;
		node->address = addrs[idx];
		log_warn("!! Bridge has switched to %s", node->address);

		if (0 == strncmp(node->address, tcp_scheme, 8)) {
			// TODO need to close old sock and reopen the ctxs
			// nng_socket *tsock = bridge_arg->sock;
			// nng_close(*tsock);
			hybrid_bridge_tcp_client(bridge_arg);
#if defined(SUPP_QUIC)
		} else if (0 == strncmp(node->address, quic_scheme, 9)) {
			hybrid_bridge_quic_client(bridge_arg);
#endif
		} else {
			log_error("Unsupported bridge protocol.");
		}
		if (bridge_arg->exec_cv) {
			nng_mtx_lock(bridge_arg->exec_mtx);
			nng_cv_wake1(bridge_arg->exec_cv);
			nng_mtx_unlock(bridge_arg->exec_mtx);
		}
		nng_mtx_lock(bridge_arg->switch_mtx);
		nng_cv_wait(bridge_arg->switch_cv);
		nng_mtx_unlock(bridge_arg->switch_mtx);
		// Free bridge client
		if (bridge_arg->client) {
			nng_aio_finish_error(bridge_arg->client->send_aio, NNG_ECLOSED);
			nng_mqtt_client_free(bridge_arg->client, true);
			bridge_arg->client = NULL;
		}
	}

	log_warn("Hybridger thread is done");
	nng_cv_free(bridge_arg->switch_cv);
	nng_mtx_free(bridge_arg->switch_mtx);
	bridge_arg->switch_cv = NULL;
	bridge_arg->switch_mtx = NULL;
}

int
hybrid_bridge_client(nng_socket *sock, conf *config, conf_bridge_node *node)
{
	bridge_param *bridge_arg;
	if ((bridge_arg = nng_alloc(sizeof(bridge_param))) == NULL) {
		log_error("memory error in allocating bridge client");
		return NNG_ENOMEM;
	}

	bridge_arg->config = node;
	bridge_arg->sock   = sock;
	bridge_arg->conf   = config;

	int rv = nng_mtx_alloc(&bridge_arg->exec_mtx);
	if (rv != 0) {
		nng_fatal("nng_mtx_alloc", rv);
		return rv;
	}
	rv = nng_cv_alloc(&bridge_arg->exec_cv, bridge_arg->exec_mtx);
	if (rv != 0) {
		nng_fatal("nng_cv_alloc", rv);
		return rv;
	}

	rv = nng_thread_create(&hybridger_thr, hybridger_cb, (void *)bridge_arg);
	if (rv != 0) {
		nng_fatal("nng_thread_create", rv);
		return rv;
	}

	nng_mtx_lock(bridge_arg->exec_mtx);
	nng_cv_wait(bridge_arg->exec_cv);
	nng_mtx_unlock(bridge_arg->exec_mtx);
	nng_cv_free(bridge_arg->exec_cv);
	bridge_arg->exec_cv = NULL;

	return rv;
}

#endif


/**
 * independent callback API for bridging aio
 */
void bridge_send_cb(void *arg)
{
	int rv;
	nng_msg *msg = NULL;
	nng_aio *aio;
	conf_bridge_node *node = arg;

	log_debug("bridge to %s msg sent", node->address);
}

int
bridge_client(nng_socket *sock, conf *config, conf_bridge_node *node)
{
	int rv;

	char *quic_scheme = "mqtt-quic";
	char *tcp_scheme  = "mqtt-tcp";
	char *tls_scheme  = "tls+mqtt-tcp";
	if (0 == strncmp(node->address, tcp_scheme, 8) ||
	    0 == strncmp(node->address, tls_scheme, 12)) {
		bridge_tcp_client(sock, config, node);
#if defined(SUPP_QUIC)
	} else if (0 == strncmp(node->address, quic_scheme, 9)) {
		bridge_quic_client(sock, config, node);
#endif
	} else {
		log_error("Unsupported bridge protocol.\n");
	}
	// alloc an AIO for each ctx bridging use only
	node->bridge_aio = nng_alloc(
	    (config->parallel + node->parallel * 2) * sizeof(nng_aio *));

	for (uint32_t num = 0; num < (config->parallel + node->parallel * 2);
	     num++) {
		if ((rv = nng_aio_alloc(
		         &node->bridge_aio[num], bridge_send_cb, node)) != 0) {
			nng_fatal("bridge_aio nng_aio_alloc", rv);
		}
		log_debug("parallel %d", num);
	}
	return 0;
}
