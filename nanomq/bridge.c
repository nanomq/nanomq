#include "include/bridge.h"
#include "nng/mqtt/mqtt_client.h"
#include "nng/nng.h"
#include "nng/protocol/mqtt/mqtt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "include/nanomq.h"

static void
fatal(const char *func, int rv)
{
	fprintf(stderr, "%s: %s\n", func, nng_strerror(rv));
}

nng_msg *
bridge_publish_msg(const char *topic, uint8_t *payload, uint32_t len, bool dup,
    uint8_t qos, bool retain)
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
	debug_msg("publish to '%s'", topic);

	return pubmsg;
}

// Disconnect message callback function
static void
disconnect_cb(nng_pipe p, nng_pipe_ev ev, void *arg)
{
	int reason;
	nng_msg * msg = arg;
	nng_msg_free(msg);	// free connmsg
	// get connect reason
	nng_pipe_get_int(p, NNG_OPT_MQTT_DISCONNECT_REASON, &reason);
	// property *prop;
	// nng_pipe_get_ptr(p, NNG_OPT_MQTT_DISCONNECT_PROPERTY, &prop);
	debug_msg("bridge client disconnected! RC [%d] \n", reason);
}

// Connack message callback function
static void
bridge_connect_cb(nng_pipe p, nng_pipe_ev ev, void *arg)
{
	// Connected succeed
	bridge_param *param = arg;
	int reason;
	// get connect reason
	nng_pipe_get_int(p, NNG_OPT_MQTT_CONNECT_REASON, &reason);
	// get property for MQTT V5
	// property *prop;
	// nng_pipe_get_ptr(p, NNG_OPT_MQTT_CONNECT_PROPERTY, &prop);
	debug_msg("bridge client connected! RC [%d] \n", reason);

}

static void
sub_callback(void *arg) {
	nng_mqtt_client *client = (nng_mqtt_client *) arg;
	nng_aio *aio = client->sub_aio;
	nng_msg *msg = nng_aio_get_msg(aio);
	uint32_t count;
	uint8_t *code;
	if (msg) {
		code = (reason_code *)nng_mqtt_msg_get_suback_return_codes(msg, &count);
		debug_msg("suback %d \n", *(code));
	}
	debug_msg("bridge: Sub result %d \n", nng_aio_result(aio));
	nng_msg_free(msg);
	// nng_free(client, sizeof(*client));
}

int
bridge_client(nng_socket *sock, conf *config, conf_bridge_node *node)
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
	nng_socket_set(*sock, NANO_CONF, node, sizeof(conf_bridge_node));

	if ((rv = nng_dialer_create(&dialer, *sock, node->address))) {
		fatal("nng_dialer_create", rv);
		return rv;
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

	bridge_arg         = (bridge_param *) nng_alloc(sizeof(bridge_param));
	bridge_arg->config = node;
	bridge_arg->sock   = sock;
	node->sock         = (void *) sock;

	nng_dialer_set_ptr(dialer, NNG_OPT_MQTT_CONNMSG, connmsg);
	nng_mqtt_set_connect_cb(*sock, bridge_connect_cb, bridge_arg);
	nng_mqtt_set_disconnect_cb(*sock, disconnect_cb, connmsg);

	nng_dialer_start(dialer, NNG_FLAG_NONBLOCK);


	/* MQTT V5 SUBSCRIBE */
	if (bridge_arg->config->sub_count > 0) {
		nng_mqtt_topic_qos *topic_qos =
		    nng_mqtt_topic_qos_array_create(bridge_arg->config->sub_count);
		for (size_t i = 0; i < bridge_arg->config->sub_count; i++) {
			nng_mqtt_topic_qos_array_set(topic_qos, i,
			    bridge_arg->config->sub_list[i].topic,
			    bridge_arg->config->sub_list[i].qos);
		}

		nng_mqtt_client *client =
		    nng_mqtt_client_alloc(*sock, sub_callback, true);
		//Property?
		rv = nng_mqtt_subscribe_async(
		    client, topic_qos, bridge_arg->config->sub_count, NULL);
		nng_mqtt_topic_qos_array_free(
		    topic_qos, bridge_arg->config->sub_count);
	}
	return 0;
}