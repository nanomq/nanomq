// Author: wangha <wangwei at emqx dot io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

//
// This is just a simple MQTT client demonstration application.
//
// The application has three sub-commands: `conn` `pub` and `sub`.
// The `conn` sub-command connects to the server.
// The `pub` sub-command publishes a given message to the server and then exits.
// The `sub` sub-command subscribes to the given topic filter and blocks
// waiting for incoming messages.
//
// # Example:
//
// Connect to the specific server:
// ```
// $ ./quic_client conn 'mqtt-quic://127.0.0.1:14567'
// ```
//
// Subscribe to `topic` and waiting for messages:
// ```
// $ ./quic_client sub 'mqtt-tcp://127.0.0.1:14567' topic
// ```
//
// Publish 'hello' to `topic`:
// ```
// $ ./quic_client pub 'mqtt-tcp://127.0.0.1:14567' topic hello
// ```
//

#if defined(SUPP_QUIC)

#include <nng/nng.h>
#include <nng/mqtt/mqtt_client.h>
#include <nng/mqtt/mqtt_quic.h>
#include <nng/supplemental/util/platform.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static nng_socket * g_sock;

static nng_msg *
mqtt_msg_compose(int type, int qos, char *topic, char *payload)
{
	// Mqtt connect message
	nng_msg *msg;
	nng_mqtt_msg_alloc(&msg, 0);

	if (type == 1) {
		nng_mqtt_msg_set_packet_type(msg, NNG_MQTT_CONNECT);

		nng_mqtt_msg_set_connect_keep_alive(msg, 60);
		nng_mqtt_msg_set_connect_clean_session(msg, false);
	} else if (type == 2) {
		nng_mqtt_msg_set_packet_type(msg, NNG_MQTT_SUBSCRIBE);

		int count = 1;

		nng_mqtt_topic_qos subscriptions[] = {
			{
				.qos   = qos,
				.topic = {
					.buf    = (uint8_t *) topic,
					.length = strlen(topic)
				}
			},
		};

		nng_mqtt_msg_set_subscribe_topics(msg, subscriptions, count);
	} else if (type == 3) {
		nng_mqtt_msg_set_packet_type(msg, NNG_MQTT_PUBLISH);

		nng_mqtt_msg_set_publish_dup(msg, 0);
		nng_mqtt_msg_set_publish_qos(msg, qos);
		nng_mqtt_msg_set_publish_retain(msg, 0);
		nng_mqtt_msg_set_publish_topic(msg, topic);
		nng_mqtt_msg_set_publish_payload(
		    msg, (uint8_t *) payload, strlen(payload));
	}

	return msg;
}

static int
connect_cb(void *rmsg, void * arg)
{
	printf("[Connected][%s]...\n", (char *)arg);
	return 0;
}

static int
disconnect_cb(void *rmsg, void * arg)
{
	printf("[Disconnected][%s]...\n", (char *)arg);
	return 0;
}

static int
msg_send_cb(void *rmsg, void * arg)
{
	printf("[Msg Sent][%s]...\n", (char *)arg);
	return 0;
}

static int
msg_recv_cb(void *rmsg, void * arg)
{
	printf("[Msg Arrived][%s]...\n", (char *)arg);
	nng_msg *msg = rmsg;
	uint32_t topicsz, payloadsz;

	char *topic   = (char *)nng_mqtt_msg_get_publish_topic(msg, &topicsz);
	char *payload = (char *)nng_mqtt_msg_get_publish_payload(msg, &payloadsz);

	printf("topic   => %.*s\n"
	       "payload => %.*s\n",topicsz, topic, payloadsz, payload);
	return 0;
}

static int
client(int type, const char *url, const char *qos, const char *topic, const char *data)
{
	nng_socket  sock;
	int         rv, sz, q;
	nng_msg *   msg;
	const char *arg = "CLIENT FOR QUIC";

	if ((rv = nng_mqtt_quic_client_open(&sock, url)) != 0) {
		printf("error in quic client open.\n");
	}
	if (0 != nng_mqtt_quic_set_connect_cb(&sock, connect_cb, (void *)arg) ||
	    0 != nng_mqtt_quic_set_disconnect_cb(&sock, disconnect_cb, (void *)arg) ||
	    0 != nng_mqtt_quic_set_msg_recv_cb(&sock, msg_recv_cb, (void *)arg) ||
	    0 != nng_mqtt_quic_set_msg_send_cb(&sock, msg_send_cb, (void *)arg)) {
		printf("error in quic client cb set.\n");
	}
	g_sock = &sock;

	// MQTT Connect...
	msg = mqtt_msg_compose(1, 0, NULL, NULL);
	nng_sendmsg(sock, msg, NNG_FLAG_ALLOC);

	if (qos) {
		q = atoi(qos);
		if (q < 0 || q > 2) {
			printf("Qos should be in range(0~2).\n");
			q = 0;
		}
	}

	switch (type) {
	case 1:
		break;
	case 2:
		msg = mqtt_msg_compose(2, q, (char *)topic, NULL);
		nng_sendmsg(*g_sock, msg, NNG_FLAG_ALLOC);

		break;
	case 3:
		msg = mqtt_msg_compose(3, q, (char *)topic, (char *)data);
		nng_sendmsg(*g_sock, msg, NNG_FLAG_ALLOC);

		break;
	default:
		printf("Unknown command.\n");
	}

	for (;;)
		nng_msleep(1000);

	nng_close(sock);

	return (0);
}

static void
printf_helper(char *exec)
{
	fprintf(stderr, "Usage: %s conn <url>\n"
	                "       %s sub  <url> <qos> <topic>\n"
	                "       %s pub  <url> <qos> <topic> <data>\n", exec, exec, exec);
	exit(EXIT_FAILURE);
}

int
quic_client(int argc, char **argv)
{
	int rc;

	if (argc < 3)
		printf_helper(argv[0]);
	if (0 == strncmp(argv[1], "conn", 4) && argc == 3)
		client(1, argv[2], NULL, NULL, NULL);
	if (0 == strncmp(argv[1], "sub", 3)  && argc == 5)
		client(2, argv[2], argv[3], argv[4], NULL);
	if (0 == strncmp(argv[1], "pub", 3)  && argc == 6)
		client(3, argv[2], argv[3], argv[4], argv[5]);

	printf_helper(argv[0]);
	return 0;
}

#endif
