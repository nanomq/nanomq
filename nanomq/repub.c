#include "include/repub.h"
#include "nng/mqtt/mqtt_client.h"
#include "nng/nng.h"
#include "nng/protocol/mqtt/mqtt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "include/nanomq.h"

#if defined(SUPP_RULE_ENGINE)
static void
fatal(const char *func, int rv)
{
	fprintf(stderr, "%s: %s\n", func, nng_strerror(rv));
}

int
nano_client_publish(nng_socket *sock, const char *topic, uint8_t *payload,
    uint32_t len, uint8_t qos, property *props)
{
	int rv;

	// create a PUBLISH message
	nng_msg *pubmsg;
	nng_mqtt_msg_alloc(&pubmsg, 0);
	nng_mqtt_msg_set_packet_type(pubmsg, NNG_MQTT_PUBLISH);
	nng_mqtt_msg_set_publish_dup(pubmsg, true);
	nng_mqtt_msg_set_publish_qos(pubmsg, qos);
	nng_mqtt_msg_set_publish_payload(pubmsg, payload, len);
	nng_mqtt_msg_set_publish_topic(pubmsg, topic);
	if (props) {
		nng_mqtt_msg_set_publish_property(pubmsg, props);
	}

	if ((rv = nng_sendmsg(*sock, pubmsg, NNG_FLAG_ALLOC)) != 0) {
		// fatal("nng_sendmsg", rv);
	}

	return 0;
}


// Disconnect message callback function
static void
disconnect_cb(nng_pipe p, nng_pipe_ev ev, void *arg)
{
	debug_msg("bridge client disconnected!\n");
}

// Connack message callback function
static void
connect_cb(nng_pipe p, nng_pipe_ev ev, void *arg)
{
	debug_msg("nano client connected!\n");
}

int
nano_client(nng_socket *sock, repub_t *repub)
{
	int           rv;
	nng_dialer    dialer;

	if (repub->proto_ver == MQTT_PROTOCOL_VERSION_v5) {
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

	if ((rv = nng_dialer_create(&dialer, *sock, repub->address))) {
		fatal("nng_dialer_create", rv);
		return rv;
	}

	// create a CONNECT message
	/* CONNECT */
	nng_msg *connmsg;
	nng_mqtt_msg_alloc(&connmsg, 0);
	nng_mqtt_msg_set_packet_type(connmsg, NNG_MQTT_CONNECT);
	nng_mqtt_msg_set_connect_keep_alive(connmsg, repub->keepalive);
	nng_mqtt_msg_set_connect_proto_version(connmsg, repub->proto_ver);
	nng_mqtt_msg_set_connect_clean_session(connmsg, repub->clean_start);
	if (repub->clientid) {
		nng_mqtt_msg_set_connect_client_id(connmsg, repub->clientid);
	}
	if (repub->username) {
		nng_mqtt_msg_set_connect_user_name(connmsg, repub->username);
	}
	if (repub->password) {
		nng_mqtt_msg_set_connect_password(connmsg, repub->password);
	}

	repub->sock = (void *) sock;

	nng_dialer_set_ptr(dialer, NNG_OPT_MQTT_CONNMSG, connmsg);
	nng_mqtt_set_connect_cb(*sock, connect_cb, repub);
	nng_mqtt_set_disconnect_cb(*sock, disconnect_cb, connmsg);

	nng_dialer_start(dialer, NNG_FLAG_NONBLOCK);

	return 0;
}
#endif