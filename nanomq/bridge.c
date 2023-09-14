#include "include/bridge.h"
#include "nng/mqtt/mqtt_client.h"
#include "nng/nng.h"
#include "nng/protocol/mqtt/mqtt.h"
#include "nng/supplemental/nanolib/log.h"
#include "nng/supplemental/util/platform.h"
#include "nng/supplemental/nanolib/utils.h"
#include "nng/protocol/mqtt/mqtt_parser.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "include/nanomq.h"
#include "include/mqtt_api.h"

#ifdef SUPP_QUIC
#include "nng/mqtt/mqtt_quic_client.h"
#endif

#ifdef NNG_SUPP_TLS
#include "nng/supplemental/tls/tls.h"
static int init_dialer_tls(nng_dialer d, const char *cacert, const char *cert,
    const char *key, const char *pass);
#endif

static const char *quic_scheme = "mqtt-quic";
static const char *tcp_scheme  = "mqtt-tcp";
static const char *tls_scheme  = "tls+mqtt-tcp";

// lock is necessary for protecting nni_sock
static nng_mtx *reload_lock = NULL;

static void bridge_tcp_connect_cb(nng_pipe p, nng_pipe_ev ev, void *arg);
static void bridge_tcp_disconnect_cb(nng_pipe p, nng_pipe_ev ev, void *arg);

#if defined(SUPP_QUIC)
static void bridge_quic_connect_cb(nng_pipe p, nng_pipe_ev ev, void *arg);
static void bridge_quic_disconnect_cb(nng_pipe p, nng_pipe_ev ev, void *arg);
#endif

static property *sub_property(conf_bridge_sub_properties *conf_prop);
static property *conn_property(conf_bridge_conn_properties *conf_prop);
static property *will_property(conf_bridge_conn_will_properties *will_prop);

static nng_thread *hybridger_thr;

static void quic_ack_cb(void *arg);

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
create_connect_msg(conf_bridge_node *node)
{
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
	if (node->will_flag) {
		nng_mqtt_msg_set_connect_will_topic(connmsg, node->will_topic);
		nng_mqtt_msg_set_connect_will_msg(connmsg,
		    (uint8_t *) node->will_payload,
		    strlen(node->will_payload));
		nng_mqtt_msg_set_connect_will_qos(connmsg, node->will_qos);
		nng_mqtt_msg_set_connect_will_retain(
		    connmsg, node->will_retain);
	}

	if (node->proto_ver == MQTT_PROTOCOL_VERSION_v5) {
		property *properties = conn_property(node->conn_properties);
		nng_mqtt_msg_set_connect_property(connmsg, properties);
		if (node->will_flag) {
			property *will_properties =
			    will_property(node->will_properties);
			nng_mqtt_msg_set_connect_will_property(
			    connmsg, will_properties);
		}
	}
	nng_mqtt_msg_encode(connmsg);
	return connmsg;
}

nng_msg *
create_disconnect_msg()
{
	nng_msg *msg;
	if (0 != nng_mqtt_msg_alloc(&msg, 0))
		return NULL;

	nng_mqtt_msg_set_packet_type(msg, NNG_MQTT_DISCONNECT);
	nng_mqtt_msg_set_disconnect_reason_code(msg, NORMAL_DISCONNECTION);

	return msg;
}

int
bridge_handle_sub_reflection(nano_work *work, conf_bridge *bridge, char *topic, int *len)
{
	for (size_t t = 0; t < bridge->count; t++) {
		conf_bridge_node *node = bridge->nodes[t];
		if (node->enable) {
			for (size_t i = 0; i < node->sub_count; i++) {
				if (topic != NULL && node->sub_list[i]->remote_topic != NULL) {
					if (strncmp(topic, node->sub_list[i]->remote_topic, *len) == 0) {
						topics *sub_topic = node->sub_list[i];
						/* release old topic area */
						nng_free(topic, strlen(topic));

						char *local_topic = nng_alloc(sub_topic->local_topic_len + 1);
						memset(local_topic, 0, sub_topic->local_topic_len + 1);

						strncpy(local_topic, sub_topic->local_topic, sub_topic->local_topic_len);

						work->pub_packet->var_header.publish.topic_name.body = local_topic;
						work->pub_packet->var_header.publish.topic_name.len = sub_topic->local_topic_len;

						topic = work->pub_packet->var_header.publish.topic_name.body;
						*len = work->pub_packet->var_header.publish.topic_name.len;

						return 0;
					}
				}
			}
		}
	}
	return -1;
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
	log_debug("bridge: publish to '%s'", topic);

	return pubmsg;
}

static void
send_callback(nng_mqtt_client *client, nng_msg *msg, void *obj)
{
	nng_aio *        aio    = client->send_aio;

	if (nng_aio_result(aio) != 0) {
		return;
	}

	uint32_t         count;
	uint8_t *        code;
	uint8_t          type;

	if (msg == NULL || nng_aio_result(aio) != 0)
		return;
	type = nng_msg_get_type(msg);
	if (type == CMD_SUBACK) {
		code = nng_mqtt_msg_get_suback_return_codes(msg, &count);
		log_info("bridge: subscribe aio result %d", nng_aio_result(aio));
		for (int i=0; i<count; ++i) {
			log_info("bridge: suback code %d ", *(code + i));
		}
		nng_msg_free(msg);
	} else if(type == CMD_CONNECT) {
		log_debug("send bridge connect msg complete");
	}
	// nng_mqtt_client_free(client, true);
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
will_property(conf_bridge_conn_will_properties *will_prop)
{
	if (will_prop) {
		property *link_list = mqtt_property_alloc();
		property *prop;
		if (will_prop->payload_format_indicator != 0) {
			prop = mqtt_property_set_value_u8(
			    PAYLOAD_FORMAT_INDICATOR,
			    will_prop->payload_format_indicator);
			mqtt_property_append(link_list, prop);
		}
		if (will_prop->message_expiry_interval != 0) {
			prop = mqtt_property_set_value_u32(
			    MESSAGE_EXPIRY_INTERVAL,
			    will_prop->message_expiry_interval);
			mqtt_property_append(link_list, prop);
		}
		if (will_prop->content_type) {
			prop = mqtt_property_set_value_str(CONTENT_TYPE,
			    will_prop->content_type,
			    strlen(will_prop->content_type), false);
			mqtt_property_append(link_list, prop);
		}
		if (will_prop->response_topic) {
			prop = mqtt_property_set_value_str(RESPONSE_TOPIC,
			    will_prop->response_topic,
			    strlen(will_prop->response_topic), false);
			mqtt_property_append(link_list, prop);
		}
		if (will_prop->correlation_data) {
			prop = mqtt_property_set_value_str(CORRELATION_DATA,
			    will_prop->correlation_data,
			    strlen(will_prop->correlation_data), false);
			mqtt_property_append(link_list, prop);
		}
		if (will_prop->will_delay_interval != 0) {
			prop = mqtt_property_set_value_u32(WILL_DELAY_INTERVAL,
			    will_prop->will_delay_interval);
			mqtt_property_append(link_list, prop);
		}
		if (will_prop->user_property_size > 0 &&
		    will_prop->user_property) {
			for (size_t i = 0; i < will_prop->user_property_size;
			     i++) {
				prop = mqtt_property_set_value_strpair(
				    USER_PROPERTY,
				    will_prop->user_property[i]->key,
				    strlen(will_prop->user_property[i]->key),
				    will_prop->user_property[i]->value,
				    strlen(will_prop->user_property[i]->value),
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

static void
hybrid_tcp_connect_cb(nng_pipe p, nng_pipe_ev ev, void *arg)
{
	bridge_tcp_connect_cb(p, ev, arg);
}

// Disconnect message callback function for hybrid bridging
static void
hybrid_tcp_disconnect_cb(nng_pipe p, nng_pipe_ev ev, void *arg)
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

static int
hybrid_tcp_client(bridge_param *bridge_arg)
{
	int           rv;
	nng_dialer    dialer;

	nng_socket *new = (nng_socket *) nng_alloc(sizeof(nng_socket));
	conf_bridge_node *node = bridge_arg->config;

	if (node->proto_ver == MQTT_PROTOCOL_VERSION_v5) {
		if ((rv = nng_mqttv5_client_open(new)) != 0) {
			nng_fatal("nng_mqttv5_client_open", rv);
			return rv;
		}
	} else {
		if ((rv = nng_mqtt_client_open(new)) != 0) {
			nng_fatal("nng_mqtt_client_open", rv);
			return rv;
		}
	}

	apply_sqlite_config(new, node, "mqtt_client.db");

	if ((rv = nng_dialer_create(&dialer, *new, node->address))) {
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

	nng_msg *connmsg   = create_connect_msg(node);
	bridge_arg->connmsg = connmsg;
	bridge_arg->client = nng_mqtt_client_alloc(*new, &send_callback, true);

	node->sock         = (void *) new;
	bridge_arg->sock   = new;

	// TCP bridge does not support hot update of connmsg
	nng_dialer_set_ptr(dialer, NNG_OPT_MQTT_CONNMSG, connmsg);
	nng_socket_set_ptr(*new, NNG_OPT_MQTT_CONNMSG, connmsg);
	nng_mqtt_set_connect_cb(*new, hybrid_tcp_connect_cb, bridge_arg);
	nng_mqtt_set_disconnect_cb(*new, hybrid_tcp_disconnect_cb, bridge_arg);

	nng_dialer_start(dialer, NNG_FLAG_NONBLOCK);

	return 0;
}

#if defined(SUPP_QUIC)
// Disconnect message callback function
static void
hybrid_quic_disconnect_cb(nng_pipe p, nng_pipe_ev ev, void *arg)
{
	int reason = 0;
	nng_pipe_get_int(p, NNG_OPT_MQTT_DISCONNECT_REASON, &reason);
	log_warn("quic bridge client disconnected! RC [%d] \n", reason);
	bridge_param *bridge_arg = arg;

	nng_mtx_lock(bridge_arg->switch_mtx);
	nng_cv_wake1(bridge_arg->switch_cv);
	nng_mtx_unlock(bridge_arg->switch_mtx);
}

static void
hybrid_quic_connect_cb(nng_pipe p, nng_pipe_ev ev, void *arg)
{
	bridge_quic_connect_cb(p, ev, arg);
}

static int
hybrid_quic_client(bridge_param *bridge_arg)
{
	int           rv;
	nng_dialer    dialer;
	log_info("Quic bridge service start.");

	// always alloc a new sock pointer in hybrid mode
	nng_socket *new = (nng_socket *) nng_alloc(sizeof(nng_socket));
	conf_bridge_node* node = bridge_arg->config;

	// keepalive here is for QUIC only
	if (node->proto_ver == MQTT_PROTOCOL_VERSION_v5) {
		log_info("MQTT V5 OVER QUIC is not supported yet.");
		/*
		if ((rv = nng_mqtt_quic_client_open(new)) != 0) {
			nng_fatal("nng_mqtt_quic_client_open", rv);
			return rv;
		}
		*/
	} else {
		if ((rv = nng_mqtt_quic_client_open(new)) != 0) {
			nng_fatal("nng_mqtt_quic_client_open", rv);
			return rv;
		}
	}

	// TODO mqtt v5 protocol
	apply_sqlite_config(new, node, "mqtt_quic_client.db");

	if ((rv = nng_dialer_create(&dialer, *new, node->address))) {
		nng_fatal("nng_dialer_create", rv);
		return rv;
	}

	nng_msg *connmsg   = create_connect_msg(node);
	bridge_arg->connmsg = connmsg;
	bridge_arg->client = nng_mqtt_client_alloc(*new, &send_callback, true);

	node->sock         = (void *) new;
	bridge_arg->sock   = new;

	// TCP bridge does not support hot update of connmsg
	nng_dialer_set_ptr(dialer, NNG_OPT_MQTT_CONNMSG, connmsg);
	nng_socket_set_ptr(*new, NNG_OPT_MQTT_CONNMSG, connmsg);
	nng_mqtt_set_connect_cb(*new, hybrid_quic_connect_cb, bridge_arg);
	nng_mqtt_set_disconnect_cb(*new, hybrid_quic_disconnect_cb, bridge_arg);

	nng_dialer_start(dialer, NNG_FLAG_NONBLOCK);

	return 0;
}
#endif

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
	// alloc an AIO for each ctx bridging use only
	node->bridge_aio =
	    nng_alloc((bridge_arg->conf->parallel + node->parallel * 2) *
	        sizeof(nng_aio *));

	for (uint32_t num = 0;
	     num < (bridge_arg->conf->parallel + node->parallel * 2); num++) {
		if ((rv = nng_aio_alloc(&node->bridge_aio[num], NULL, node)) !=
		    0) {
			nng_fatal("bridge_aio nng_aio_alloc", rv);
		}
		log_debug("parallel %d", num);
	}

	char addr_back[160] = {'\0'};
	if (0 != gen_fallback_url(node->address, addr_back))
		strcpy(addr_back, node->address);
	char * addrs[] = {node->address, addr_back};
	int idx = -1;
	for (;;) {
		// Get next bridge node
		nng_socket *tsock = bridge_arg->sock;
		idx = (idx + 1) % 2;
		node->address = addrs[idx];
		log_warn("!! Bridge has switched to %s", node->address);

		if (0 == strncmp(node->address, tcp_scheme, strlen(tcp_scheme)) ||
		    0 == strncmp(node->address, tls_scheme, strlen(tls_scheme))) {
			hybrid_tcp_client(bridge_arg);
			nng_socket *nsock = bridge_arg->sock;
			if (tsock != nsock) {
				nng_sock_replace(*tsock, *nsock);
				nng_close(*tsock);
				nng_free(tsock, sizeof(nng_socket));
			}
#if defined(SUPP_QUIC)
		} else if (0 ==
		    strncmp(node->address, quic_scheme, strlen(quic_scheme))) {
			hybrid_quic_client(bridge_arg);
			nng_socket *nsock = bridge_arg->sock;
			if (tsock != nsock) {
				nng_sock_replace(*tsock, *nsock);
				nng_close(*tsock);
				nng_free(tsock, sizeof(nng_socket));
			}
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
	if (reload_lock == NULL) {
		nng_mtx_alloc(&reload_lock);
	}

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

#if defined(SUPP_QUIC)

static void
quic_ack_cb(void *arg)
{
	int result = 0;

	nng_aio *     aio   = arg;
	bridge_param *param = nng_aio_get_prov_data(aio);
	nng_socket *  sock  = param->sock;
	nng_msg *     msg   = nng_aio_get_msg(aio);
	if (msg == NULL || (result = nng_aio_result(aio)) != 0) {
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
				nng_mqtt_topic_qos_array_set(topic_qos, i,
				    param->config->sub_list[i]->topic,
				    param->config->sub_list[i]->qos, 1,
				    param->config->sub_list[i]
				        ->retain_as_published,
				    param->config->sub_list[i]
				        ->retain_handling);
				log_info("Bridge client subscribed topic %s "
				         "(qos %d rap %d rh %d).",
				    param->config->sub_list[i]->topic,
				    param->config->sub_list[i]->qos,
				    param->config->sub_list[i]
				        ->retain_as_published,
				    param->config->sub_list[i]
				        ->retain_handling);

				property *properties = NULL;
				if (param->config->proto_ver ==
				    MQTT_PROTOCOL_VERSION_v5) {
					properties = sub_property(
					    param->config->sub_properties);
				}
				nng_mqtt_subscribe_async(
				    client, topic_qos, 1, properties);
				nng_mqtt_topic_qos_array_free(topic_qos, 1);
			}
		} else {
			nng_mqtt_topic_qos *topic_qos =
			    nng_mqtt_topic_qos_array_create(
			        param->config->sub_count);
			for (size_t i = 0; i < param->config->sub_count; i++) {
				nng_mqtt_topic_qos_array_set(topic_qos, i,
				    param->config->sub_list[i]->topic,
				    param->config->sub_list[i]->qos, 1,
				    param->config->sub_list[i]
				        ->retain_as_published,
				    param->config->sub_list[i]
				        ->retain_handling);
				log_info("Bridge client subscribed topic %s "
				         "(qos %d rap %d rh %d).",
				    param->config->sub_list[i]->topic,
				    param->config->sub_list[i]->qos,
				    param->config->sub_list[i]
				        ->retain_as_published,
				    param->config->sub_list[i]
				        ->retain_handling);
			}
			property *properties = NULL;
			if (param->config->proto_ver ==
			    MQTT_PROTOCOL_VERSION_v5) {
				properties = sub_property(
				    param->config->sub_properties);
			}
			nng_mqtt_subscribe_async(client, topic_qos,
			    param->config->sub_count, properties);
			nng_mqtt_topic_qos_array_free(
			    topic_qos, param->config->sub_count);
		}
	}

	log_debug("ACK msg is recevied in bridging");

	nng_msg_free(msg);
	nng_aio_set_msg(aio, NULL);
	// To clean the cached msg if any
	nng_recv_aio(*sock, aio);
}

static int execone = 1;

// Connack message callback function
static void
bridge_quic_connect_cb(nng_pipe p, nng_pipe_ev ev, void *arg)
{
	// Connected succeed
	bridge_param *param  = arg;
	int           reason = 0;
	char         *addr;
	uint16_t      port;

	if (execone == 0) {
		return;
	}

	// get connect reason
	nng_pipe_get_int(p, NNG_OPT_MQTT_CONNECT_REASON, &reason);
	addr = nano_pipe_get_local_address(p);
	port = nano_pipe_get_local_port(p);
	// get property for MQTT V5
	// property *prop;
	// nng_pipe_get_ptr(p, NNG_OPT_MQTT_CONNECT_PROPERTY, &prop);
	log_info("Bridge client connected! RC [%d]", reason);
	log_info("Local ip4 address [%s] port [%d]", addr, port);

	if (reason == 0 && param->config->sub_count > 0) {
		nng_mqtt_client *client = param->client;
		for (size_t i = 0; i < param->config->sub_count; i++) {
			nng_mqtt_topic_qos *topic_qos =
			    nng_mqtt_topic_qos_array_create(1);
			nng_mqtt_topic_qos_array_set(topic_qos, 0,
			    param->config->sub_list[i]->topic,
			    param->config->sub_list[i]->qos, 1, 0, 0);
			log_info("Quic bridge client subscribe to "
			         "topic (QoS %d)%s.",
			    param->config->sub_list[i]->qos,
			    param->config->sub_list[i]->topic);

			property *properties = NULL;
			if (param->config->proto_ver ==
			    MQTT_PROTOCOL_VERSION_v5) {
				properties = sub_property(
				    param->config->sub_properties);
			}
			nng_mqtt_subscribe_async(
			    client, topic_qos, 1, properties);
			nng_mqtt_topic_qos_array_free(topic_qos, 1);
		}
		execone = 0;
	}

	if (addr)
		free(addr);
}

// Disconnect message callback function
static void
bridge_quic_disconnect_cb(nng_pipe p, nng_pipe_ev ev, void *arg)
{
	int reason = 0;
	// get connect reason
	nng_pipe_get_int(p, NNG_OPT_MQTT_DISCONNECT_REASON, &reason);
	// property *prop;
	// nng_pipe_get_ptr(p, NNG_OPT_MQTT_DISCONNECT_PROPERTY, &prop);
	log_warn("bridge client disconnected! RC [%d] \n", reason);

	bridge_param *bridge_arg = arg;
	// Free cparam kept
	// void *cparam = nng_msg_get_conn_param(bridge_arg->connmsg);
	// if (cparam != NULL)
	//  conn_param_free(cparam);
	// nng_msg_free(bridge_arg->connmsg);
	// bridge_arg->connmsg = NULL;
}

static int
bridge_quic_reload(nng_socket *sock, conf *config, conf_bridge_node *node, bridge_param *bridge_arg)
{
	int           rv;
	nng_dialer    dialer;

	if (node->proto_ver == MQTT_PROTOCOL_VERSION_v5) {
		if ((rv = nng_mqttv5_client_open(sock)) != 0) {
			nng_fatal("nng_mqttv5_client_open", rv);
			return rv;
		}
	} else {
		if ((rv = nng_mqtt_quic_client_open(sock)) != 0) {
			nng_fatal("nng_mqtt_client_open", rv);
			return rv;
		}
	}

	apply_sqlite_config(sock, node, "mqtt_quic_client.db");

	if ((rv = nng_dialer_create(&dialer, *sock, node->address))) {
		nng_fatal("nng_dialer_create", rv);
		return rv;
	}
	// set backoff param to 24s
	nng_duration duration = 240000;
	nng_dialer_set(dialer, NNG_OPT_MQTT_RECONNECT_BACKOFF_MAX, &duration, sizeof(nng_duration));

	bridge_arg->client->sock = *sock;

	// create a CONNECT message
	nng_msg *connmsg = create_connect_msg(node);
	bridge_arg->connmsg = connmsg;

	execone = 1;

	// TCP bridge does not support hot update of connmsg
	if (0 != nng_dialer_set_ptr(dialer, NNG_OPT_MQTT_CONNMSG, connmsg)) {
		log_warn("Error in updating connmsg");
	}
	if (0 != nng_socket_set_ptr(*sock, NNG_OPT_MQTT_CONNMSG, connmsg)) {
		log_warn("Error in updating connmsg");
	}
	nng_mqtt_set_connect_cb(*sock, bridge_quic_connect_cb, bridge_arg);
	nng_mqtt_set_disconnect_cb(*sock, bridge_quic_disconnect_cb, bridge_arg);
	nng_dialer_start(dialer, NNG_FLAG_NONBLOCK);

	return 0;
}

static int
bridge_quic_client(nng_socket *sock, conf *config, conf_bridge_node *node, bridge_param *bridge_arg)
{
	int           rv;
	nng_dialer    dialer;
	log_debug("Quic bridge service start.\n");

	if (node->proto_ver == MQTT_PROTOCOL_VERSION_v5) {
		if ((rv = nng_mqtt_quic_client_open(sock)) != 0) {
			nng_fatal("nng_mqttv5_quic_client_open", rv);
			return rv;
		}
	} else {
		if ((rv = nng_mqtt_quic_client_open(sock)) != 0) {
			nng_fatal("nng_mqtt_quic_client_open", rv);
			return rv;
		}
	}

	apply_sqlite_config(sock, node, "mqtt_quic_client.db");

	if ((rv = nng_dialer_create(&dialer, *sock, node->address))) {
		nng_fatal("nng_dialer_create", rv);
		return rv;
	}
	// set backoff param to 24s
	nng_duration duration = 240000;
	nng_dialer_set(dialer, NNG_OPT_MQTT_RECONNECT_BACKOFF_MAX, &duration, sizeof(nng_duration));
	// nng_dialer_set_bool(dialer, NNG_OPT_QUIC_ENABLE_0RTT, true);
	// nng_dialer_set_bool(dialer, NNG_OPT_QUIC_ENABLE_MULTISTREAM, true);

	bridge_arg->client = nng_mqtt_client_alloc(*sock, &send_callback, true);

	// create a CONNECT message
	nng_msg *connmsg = create_connect_msg(node);
	bridge_arg->connmsg = connmsg;

	// QUIC bridge does not support hot update of connmsg as well
	if (0 != nng_dialer_set_ptr(dialer, NNG_OPT_MQTT_CONNMSG, connmsg)) {
		log_warn("Error in updating connmsg");
	}
	if (0 != nng_socket_set_ptr(*sock, NNG_OPT_MQTT_CONNMSG, connmsg)) {
		log_warn("Error in updating connmsg");
	}
	nng_mqtt_set_connect_cb(*sock, bridge_quic_connect_cb, bridge_arg);
	nng_mqtt_set_disconnect_cb(*sock, bridge_quic_disconnect_cb, bridge_arg);

	nng_dialer_start(dialer, NNG_FLAG_NONBLOCK);

	return 0;
}
#endif

// Connack message callback function
static void
bridge_tcp_connect_cb(nng_pipe p, nng_pipe_ev ev, void *arg)
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

	/* MQTT SUBSCRIBE */
	if (reason == 0 && param->config->sub_count > 0) {
		nng_mqtt_topic_qos *topic_qos =
		    nng_mqtt_topic_qos_array_create(param->config->sub_count);
		for (size_t i = 0; i < param->config->sub_count; i++) {
			nng_mqtt_topic_qos_array_set(topic_qos, i,
			    param->config->sub_list[i]->remote_topic,
			    param->config->sub_list[i]->qos, 1,
			    param->config->sub_list[i]->retain_as_published,
			    param->config->sub_list[i]->retain_handling);
			log_info("Bridge client subscribed topic %s (qos %d rap %d rh %d).",
			    param->config->sub_list[i]->remote_topic,
			    param->config->sub_list[i]->qos,
				param->config->sub_list[i]->retain_as_published,
				param->config->sub_list[i]->retain_handling);
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

// Disconnect message callback function
static void
bridge_tcp_disconnect_cb(nng_pipe p, nng_pipe_ev ev, void *arg)
{
	int reason = 0;
	// get disconnect reason
	nng_pipe_get_int(p, NNG_OPT_MQTT_DISCONNECT_REASON, &reason);
	// property *prop;
	// nng_pipe_get_ptr(p, NNG_OPT_MQTT_DISCONNECT_PROPERTY, &prop);
	log_warn("bridge client disconnected! RC [%d] \n", reason);

	bridge_param *bridge_arg = arg;
	// Free cparam kept
	// void *cparam = nng_msg_get_conn_param(bridge_arg->connmsg);
	// if (cparam != NULL)
	//  conn_param_free(cparam);
	// nng_msg_free(bridge_arg->connmsg);
	// bridge_arg->connmsg = NULL;
}


static int
bridge_tcp_reload(nng_socket *sock, conf *config, conf_bridge_node *node, bridge_param *bridge_arg)
{
	int           rv;
	nng_dialer    dialer;

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
	// set backoff param to 24s
	nng_duration duration = 240000;
	nng_dialer_set(dialer, NNG_OPT_MQTT_RECONNECT_BACKOFF_MAX, &duration, sizeof(nng_duration));


#ifdef NNG_SUPP_TLS
	if (node->tls.enable) {
		if ((rv = init_dialer_tls(dialer, node->tls.ca, node->tls.cert,
		         node->tls.key, node->tls.key_password)) != 0) {
			nng_fatal("init_dialer_tls", rv);
		}
	}
#endif

	bridge_arg->client->sock = *sock;

	// create a CONNECT message
	nng_msg *connmsg = create_connect_msg(node);
	bridge_arg->connmsg = connmsg;

	// TCP bridge does not support hot update of connmsg
	if (0 != nng_dialer_set_ptr(dialer, NNG_OPT_MQTT_CONNMSG, connmsg)) {
		log_warn("Error in updating connmsg");
	}
	if (0 != nng_socket_set_ptr(*sock, NNG_OPT_MQTT_CONNMSG, connmsg)) {
		log_warn("Error in updating connmsg");
	}
	nng_mqtt_set_connect_cb(*sock, NULL, NULL);
	nng_mqtt_set_disconnect_cb(*sock, bridge_tcp_disconnect_cb, bridge_arg);
	nng_dialer_start(dialer, NNG_FLAG_NONBLOCK);

	if (bridge_arg->config->sub_count > 0) {
		nng_mqtt_topic_qos *topic_qos =
		    nng_mqtt_topic_qos_array_create(
		        bridge_arg->config->sub_count);
		for (size_t i = 0; i < bridge_arg->config->sub_count; i++) {
			nng_mqtt_topic_qos_array_set(topic_qos, i,
			    bridge_arg->config->sub_list[i]->remote_topic,
			    bridge_arg->config->sub_list[i]->qos, 1,
			    bridge_arg->config->sub_list[i]->retain_as_published,
			    bridge_arg->config->sub_list[i]->retain_handling);
			log_info("Bridge client subscribed topic %s (qos %d rap %d rh %d).",
			    bridge_arg->config->sub_list[i]->remote_topic,
			    bridge_arg->config->sub_list[i]->qos,
				bridge_arg->config->sub_list[i]->retain_as_published,
				bridge_arg->config->sub_list[i]->retain_handling);
		}
		nng_mqtt_client *client = bridge_arg->client;

		// Property
		property *properties = NULL;
		if (bridge_arg->config->proto_ver ==
		    MQTT_PROTOCOL_VERSION_v5) {
			properties =
			    sub_property(bridge_arg->config->sub_properties);
		}
		nng_mqtt_subscribe_async(client, topic_qos,
		    bridge_arg->config->sub_count, properties);
		nng_mqtt_topic_qos_array_free(
		    topic_qos, bridge_arg->config->sub_count);
	}
	return 0;
}


static int
bridge_tcp_client(nng_socket *sock, conf *config, conf_bridge_node *node, bridge_param *bridge_arg)
{
	int           rv;
	nng_dialer    dialer;

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
	// set backoff param to 24s
	nng_duration duration = 240000;
	nng_dialer_set(dialer, NNG_OPT_MQTT_RECONNECT_BACKOFF_MAX, &duration, sizeof(nng_duration));


#ifdef NNG_SUPP_TLS
	if (node->tls.enable) {
		if ((rv = init_dialer_tls(dialer, node->tls.ca, node->tls.cert,
		         node->tls.key, node->tls.key_password)) != 0) {
			nng_fatal("init_dialer_tls", rv);
		}
	}
#endif

	bridge_arg->client = nng_mqtt_client_alloc(*sock, &send_callback, true);
	// set retry interval as 10s
	nng_duration retry = 10000;
	nng_socket_set_ms(*sock, NNG_OPT_MQTT_RETRY_INTERVAL, retry);
	// create a CONNECT message
	nng_msg *connmsg = create_connect_msg(node);
	bridge_arg->connmsg = connmsg;

	// TCP bridge does not support hot update of connmsg
	if (0 != nng_dialer_set_ptr(dialer, NNG_OPT_MQTT_CONNMSG, connmsg)) {
		log_warn("Error in updating connmsg");
	}
	if (0 != nng_socket_set_ptr(*sock, NNG_OPT_MQTT_CONNMSG, connmsg)) {
		log_warn("Error in updating connmsg");
	}
	nng_mqtt_set_connect_cb(*sock, bridge_tcp_connect_cb, bridge_arg);
	nng_mqtt_set_disconnect_cb(*sock, bridge_tcp_disconnect_cb, bridge_arg);

	nng_dialer_start(dialer, NNG_FLAG_NONBLOCK);

	return 0;
}

/**
 * independent callback API for bridging aio
 */
void
bridge_send_cb(void *arg)
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

	bridge_param *bridge_arg;
	bridge_arg = (bridge_param *) nng_alloc(sizeof(bridge_param));
	if (bridge_arg == NULL) {
		log_error("memory error in allocating bridge client");
		return NNG_ENOMEM;
	}
	bridge_arg->config = node;
	bridge_arg->sock   = sock;
	bridge_arg->conf   = config;
	if (node->address == NULL) {
		log_error("invalid bridging config!");
		return -1;
	}
	if (reload_lock == NULL) {
		nng_mtx_alloc(&reload_lock);
	}

	if (0 == strncmp(node->address, tcp_scheme, strlen(tcp_scheme)) ||
	    0 == strncmp(node->address, tls_scheme, strlen(tls_scheme))) {
		bridge_tcp_client(sock, config, node, bridge_arg);
#if defined(SUPP_QUIC)
	} else if (0 == strncmp(node->address, quic_scheme, strlen(quic_scheme))) {
		bridge_quic_client(sock, config, node, bridge_arg);
#endif
	} else {
		nng_free(bridge_arg, sizeof(bridge_param));
		log_error("Unsupported bridge protocol.\n");
	}

	// alloc an AIO for each ctx bridging use only
	node->bridge_aio = nng_alloc(
	    (config->parallel + node->parallel * 2) * sizeof(nng_aio *));

	node->sock = (void *) sock;
	node->bridge_arg = (void *) bridge_arg;

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

int
bridge_subscribe(nng_socket *sock, conf_bridge_node *node,
        nng_mqtt_topic_qos *topic_qos, size_t sub_count, property *properties)
{
	int rv = 0;
	nng_msg *msg = NULL;
	uint8_t *rc = NULL;
	uint32_t rcsz;

	if (sub_count < 1)
		return -1;

	for (size_t i = 0; i < sub_count; i++) {
		log_info("Bridge client subscribed topic %.*s (qos %d).",
		    topic_qos[i].topic.length, topic_qos[i].topic.buf, topic_qos[i].qos);
	}
	bridge_param *bridge_arg = (bridge_param *)node->bridge_arg;

	nng_mtx_lock(reload_lock);
	// create a SUBSCRIBE message
	nng_msg *submsg;
	if (nng_mqtt_msg_alloc(&submsg, 0) != 0)
		return NNG_ENOMEM;
	nng_mqtt_msg_set_packet_type(submsg, NNG_MQTT_SUBSCRIBE);
	nng_mqtt_msg_set_subscribe_topics(submsg, topic_qos, sub_count);
	if (properties)
		nng_mqtt_msg_set_subscribe_property(submsg, properties);

	// Send message
	nng_aio *aio;
	if ((rv = nng_aio_alloc(&aio, NULL, NULL)) != 0) {
		nng_mtx_unlock(reload_lock);
		return rv;
	}
	nng_aio_set_msg(aio, submsg);
	nng_send_aio(*sock, aio);

	// Hold to get suback
	nng_aio_wait(aio);
	nng_mtx_unlock(reload_lock);

	if (nng_aio_result(aio) != 0 || (msg = nng_aio_get_msg(aio)) == NULL) {
		// Connection losted
		log_warn("Can't get suback. Maybe connection of bridge was closed.");
		rv = -3;
		goto done;
	}

	if (nng_mqtt_msg_get_packet_type(msg) != NNG_MQTT_SUBACK) {
		log_warn("Unknown error in handle bridge subscribe");
		goto done;
	}
	rc = nng_mqtt_msg_get_suback_return_codes(msg, &rcsz);
	for (int i=0; i<rcsz; ++i) {
		log_info("SUBACK reason code %d", rc[i]);
		if (rc[i] == 0x80)
			rv = -2;
	}

done:
	nng_aio_free(aio);
	if (msg)
		nng_msg_free(msg);

	return rv;
}

int
bridge_unsubscribe(nng_socket *sock, conf_bridge_node *node,
        nng_mqtt_topic *topics, size_t unsub_count, property *properties)
{
	int rv = 0;
	nng_msg *msg = NULL;
	uint8_t *rc = NULL;
	uint32_t rcsz;

	if (unsub_count < 1)
		return -1;

	for (size_t i = 0; i < unsub_count; i++) {
		log_info("Bridge client unsubscribed topic %.*s.",
		    topics[i].length, topics[i].buf);
	}
	bridge_param *bridge_arg = (bridge_param *)node->bridge_arg;

	nng_mtx_lock(reload_lock);
	// create a UNSUBSCRIBE message
	nng_msg *unsubmsg;
	if (nng_mqtt_msg_alloc(&unsubmsg, 0) != 0)
		return NNG_ENOMEM;
	nng_mqtt_msg_set_packet_type(unsubmsg, NNG_MQTT_UNSUBSCRIBE);
	nng_mqtt_msg_set_unsubscribe_topics(unsubmsg, topics, unsub_count);
	if (properties)
		nng_mqtt_msg_set_unsubscribe_property(unsubmsg, properties);

	// Send message
	nng_aio *aio;
	if ((rv = nng_aio_alloc(&aio, NULL, NULL)) != 0){
		nng_mtx_unlock(reload_lock);
		return rv;
	}
	nng_aio_set_msg(aio, unsubmsg);
	nng_send_aio(*sock, aio);

	// Hold to get suback
	nng_aio_wait(aio);
	nng_mtx_unlock(reload_lock);

	if (nng_aio_result(aio) != 0 || (msg = nng_aio_get_msg(aio)) == NULL) {
		// Connection losted
		log_warn("Can't get unsuback. Maybe connection of bridge was closed.");
		rv = -3;
		goto done;
	}

	if (nng_mqtt_msg_get_packet_type(msg) != NNG_MQTT_UNSUBACK) {
		log_warn("Unknown error in handle bridge unsubscribe");
		goto done;
	}
	rc = nng_mqtt_msg_get_unsuback_return_codes(msg, &rcsz);
	for (int i=0; i<rcsz; ++i) {
		log_info("SUBACK reason code %d", rc[i]);
		if (rc[i] == 0x80)
			rv = -2;
	}

done:
	nng_aio_free(aio);
	if (msg)
		nng_msg_free(msg);

	return rv;
}

// For now, NanoMQ only supports dynamic TCP bridging
int
bridge_reload(nng_socket *sock, conf *config, conf_bridge_node *node)
{
	if (node->address == NULL)
		return -1;

	if (0 == strncmp(node->address, tcp_scheme, strlen(tcp_scheme)) ||
	    0 == strncmp(node->address, tls_scheme, strlen(tls_scheme))) {
#if defined(SUPP_QUIC)
	} else if (0 ==
	    strncmp(node->address, quic_scheme, strlen(quic_scheme))) {
		log_info("Hot update quic bridge is an experimental function so far.");
#endif
	} else {
		log_error("Unsupported bridge protocol.\n");
	}

	nng_msg    *dismsg;
	nng_socket *tsock;
	nng_socket *new = (nng_socket *) nng_alloc(sizeof(nng_socket));

	if ((dismsg = create_disconnect_msg()) == NULL)
		return -1;

	bridge_param    *bridge_arg = (bridge_param *) node->bridge_arg;
	nng_mqtt_client *client     = bridge_arg->client;
	tsock                       = bridge_arg->sock;
	sock                        = tsock;

	// Hold on until the last sending done
	nng_aio_wait(client->send_aio);

	// Wait for the disconnect msg be sent
	nng_sendmsg(*sock, dismsg, NNG_FLAG_ALLOC);
	log_info("bridge sent disconnect to broker");

	nng_mtx_lock(reload_lock);
	node->enable = false;
	// No need to Free the nng_mqtt_client, reuse it.

	// socket reuse and open a new mqtt connection
	if (0 == strncmp(node->address, tcp_scheme, strlen(tcp_scheme)) ||
	    0 == strncmp(node->address, tls_scheme, strlen(tls_scheme))) {
		bridge_tcp_reload(new, config, node, bridge_arg);
#if defined(SUPP_QUIC)
	} else if (0 ==
	    strncmp(node->address, quic_scheme, strlen(quic_scheme))) {
		bridge_quic_reload(new, config, node, bridge_arg);
#endif
	} else {
		log_error("Unsupported bridge protocol.\n");
		nng_mtx_unlock(reload_lock);
		return -1;
	}
	if (0 == strncmp(node->address, tcp_scheme, strlen(tcp_scheme)) ||
	    0 == strncmp(node->address, tls_scheme, strlen(tls_scheme))) {
		nng_sock_replace(*tsock, *new);
		nng_close(*tsock);
		nng_free(tsock, sizeof(nng_socket));
#if defined(SUPP_QUIC)
	} else if (0 ==
	    strncmp(node->address, quic_scheme, strlen(quic_scheme))) {
		// TODO
		// nng_mqtt_quic_client_close(sock);
		nng_sock_replace(*tsock, *new);
		nng_close(*tsock);
		nng_free(tsock, sizeof(nng_socket));
#endif
	} else {
		log_error("Unsupported bridge protocol.\n");
	}
	// Update the sock in client due to it's a constant rather than pointer
	bridge_arg->client->sock = *new;
	node->sock               = new;
	node->enable             = true;
	bridge_arg->sock         = new;
	nng_mtx_unlock(reload_lock);

	return 0;
}
