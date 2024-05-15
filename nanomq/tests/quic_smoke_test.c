//
// Copyright 2024 NanoMQ Team, Inc. <wangwei@emqx.io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

// In this file. We will do some smoke tests as follows.
// * Connect and disconnect by self.
// * Connect and disconnect by peer.
// * Send and receive loop test.
// * Send and receive large message test.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <nng/mqtt/mqtt_quic_client.h>
#include <nng/mqtt/mqtt_client.h>
#include <nng/supplemental/nanolib/log.h>

#define TEST_MQTT_QUIC_URL "mqtt-quic://127.0.0.1:14567"
#define TEST_MQTT_QUIC_TOPIC "nanomq/quic/test"
#define TEST_MQTT_QUIC_PAYLOAD "aaa"

#define TEST_ROUND_COUNTER 100

nng_msg *
publish_msg()
{
	nng_msg *msg;
	nng_mqtt_msg_alloc(&msg, 0);
	nng_mqtt_msg_set_packet_type(msg, NNG_MQTT_PUBLISH);
	nng_mqtt_msg_set_publish_topic(msg, TEST_MQTT_QUIC_TOPIC);
	nng_mqtt_msg_set_publish_qos(msg, 1);
	nng_mqtt_msg_set_publish_payload(msg,
		TEST_MQTT_QUIC_PAYLOAD, strlen(TEST_MQTT_QUIC_PAYLOAD));
	return msg;
}

nng_msg *
publish_large_msg()
{
	int   len = 1024*1023; // slight less than 1MB
	char *buf = malloc(sizeof(char) * len);
	memset(buf, 'a', len);

	nng_msg *msg;
	nng_mqtt_msg_alloc(&msg, 0);
	nng_mqtt_msg_set_packet_type(msg, NNG_MQTT_PUBLISH);
	nng_mqtt_msg_set_publish_topic(msg, TEST_MQTT_QUIC_TOPIC);
	nng_mqtt_msg_set_publish_qos(msg, 1);
	nng_mqtt_msg_set_publish_payload(msg, buf, len);

	free(buf);
	return msg;
}

nng_msg *
subscribe_msg()
{
	nng_msg *msg;
	nng_mqtt_msg_alloc(&msg, 0);
	nng_mqtt_msg_set_packet_type(msg, NNG_MQTT_SUBSCRIBE);

	uint8_t qos; int cnt = 1; uint8_t nolocal;
	nng_mqtt_topic_qos *tq = nng_mqtt_topic_qos_array_create(cnt);
	assert(tq != NULL);
	nng_mqtt_topic_qos_array_set(tq, 0, TEST_MQTT_QUIC_TOPIC, qos=1, nolocal=0, 0, 0);
	nng_mqtt_msg_set_subscribe_topics(msg, tq, cnt);
	nng_mqtt_topic_qos_array_free(tq, cnt);

	return msg;
}

nng_msg *
disconnect_msg()
{
	nng_msg *msg;
	nng_mqtt_msg_alloc(&msg, 0);
	nng_mqtt_msg_set_packet_type(msg, NNG_MQTT_DISCONNECT);
	nng_mqtt_msg_set_disconnect_reason_code(msg, UNSPECIFIED_ERROR);
	return msg;
}

nng_msg *
connect_msg(uint8_t ver, char *client_id)
{
	nng_msg *msg;
	nng_mqtt_msg_alloc(&msg, 0);
	nng_mqtt_msg_set_packet_type(msg, NNG_MQTT_CONNECT);
	nng_mqtt_msg_set_connect_proto_version(msg, ver);
	nng_mqtt_msg_set_connect_keep_alive(msg, 10);
	nng_mqtt_msg_set_connect_clean_session(msg, true);
	nng_mqtt_msg_set_connect_client_id(msg, client_id);
	return msg;
}

int
connect_cb(void *rmsg, void *arg)
{
	int rv;
	nng_msg *msg = rmsg;

	rv = nng_mqtt_msg_get_connack_return_code(msg);
	printf("Connected cb, rv %d.", rv);
	nng_msg_free(msg);

	nng_aio *aio = arg;
	nng_aio_finish(aio, rv);
}

int
disconnect_cb(void *rmsg, void *arg)
{
	int rv = 0;
	printf("Disconnected reason.");

	nng_aio *aio = arg;
	nng_aio_finish(aio, rv);
}

void
con_dis_self(int id, int ver)
{
	int rv;
	nng_dialer dialer;
	nng_socket sock;
	nng_msg   *connmsg;
	char       buf[64];

	if (ver == 4)
		rv = nng_mqtt_quic_client_open(&sock);
	else if (ver == 5)
		rv = nng_mqttv5_quic_client_open(&sock);
	else {
		printf("Unsupported version.\n");
		return;
	}

	assert(rv == 0);

	rv = nng_dialer_create(&dialer, sock, TEST_MQTT_QUIC_URL);
	assert(rv == 0);

	sprintf(buf, "nanomq-quic-smoke-test-%d", id);
	connmsg = connect_msg(ver, buf);
	assert(connmsg != NULL);
	nng_dialer_set_ptr(dialer, NNG_OPT_MQTT_CONNMSG, connmsg);

	nng_aio *aio_connected;
	nng_aio_alloc(&aio_connected, NULL, NULL);
	assert(aio_connected != NULL);
	if (ver == 4)
		rv = nng_mqtt_quic_set_connect_cb(&sock, connect_cb, (void *)aio_connected);
	else if (ver == 5)
		rv = nng_mqttv5_quic_set_connect_cb(&sock, connect_cb, (void *)aio_connected);
	assert(rv == 0);

	nng_aio *aio_disconnected;
	nng_aio_alloc(&aio_disconnected, NULL, NULL);
	assert(aio_disconnected != NULL);
	if (ver == 4)
		rv = nng_mqtt_quic_set_disconnect_cb(&sock, disconnect_cb, (void *)aio_disconnected);
	else if (ver == 5)
		rv = nng_mqttv5_quic_set_disconnect_cb(&sock, disconnect_cb, (void *)aio_disconnected);
	assert(rv == 0);

	assert(true == nng_aio_begin(aio_connected));
	assert(true == nng_aio_begin(aio_disconnected));

	rv = nng_dialer_start(dialer, NNG_FLAG_ALLOC);
	assert(rv == 0 || rv == SERVER_UNAVAILABLE);
	if (rv == SERVER_UNAVAILABLE) {
		printf("[Server Unavailable] so...done\n");
		return;
	}

	printf("waiting for connected.");
	// Wait for connected
	nng_aio_wait(aio_connected);
	rv = nng_aio_result(aio_connected);
	assert(rv == 0);

	// Disconnect actively
	conn_param *cparam = nng_msg_get_conn_param(connmsg);
	nng_close(sock);

	printf("waiting for disconnected.");
	// Wait for disconnected
	nng_aio_wait(aio_disconnected);
	rv = nng_aio_result(aio_disconnected);
	assert(rv == 0);

	conn_param_free(cparam);
	nng_aio_free(aio_connected);
	nng_aio_free(aio_disconnected);
	printf("...done.\n");
}

void
con_dis_peer(int id, int ver)
{
	int rv;
	nng_dialer dialer;
	nng_socket sock;
	nng_msg   *connmsg;
	char       buf[64];

	if (ver == 4)
		rv = nng_mqtt_quic_client_open(&sock);
	else if (ver == 5)
		rv = nng_mqttv5_quic_client_open(&sock);
	else {
		printf("Unsupported version.\n");
		return;
	}

	assert(rv == 0);

	rv = nng_dialer_create(&dialer, sock, TEST_MQTT_QUIC_URL);
	assert(rv == 0);

	sprintf(buf, "nanomq-quic-smoke-test2-%d", id);
	connmsg = connect_msg(ver, buf);
	assert(connmsg != NULL);
	nng_dialer_set_ptr(dialer, NNG_OPT_MQTT_CONNMSG, connmsg);

	nng_aio *aio_connected;
	nng_aio_alloc(&aio_connected, NULL, NULL);
	assert(aio_connected != NULL);
	if (ver == 4)
		rv = nng_mqtt_quic_set_connect_cb(&sock, connect_cb, (void *)aio_connected);
	else if (ver == 5)
		rv = nng_mqttv5_quic_set_connect_cb(&sock, connect_cb, (void *)aio_connected);
	assert(rv == 0);

	nng_aio *aio_disconnected;
	nng_aio_alloc(&aio_disconnected, NULL, NULL);
	assert(aio_disconnected != NULL);
	if (ver == 4)
		rv = nng_mqtt_quic_set_disconnect_cb(&sock, disconnect_cb, (void *)aio_disconnected);
	else if (ver == 5)
		rv = nng_mqttv5_quic_set_disconnect_cb(&sock, disconnect_cb, (void *)aio_disconnected);
	assert(rv == 0);

	assert(true == nng_aio_begin(aio_connected));
	assert(true == nng_aio_begin(aio_disconnected));

	rv = nng_dialer_start(dialer, NNG_FLAG_ALLOC);
	assert(rv == 0 || rv == SERVER_UNAVAILABLE);
	if (rv == SERVER_UNAVAILABLE) {
		printf("[Server Unavailable] so...done\n");
		return;
	}

	printf("waiting for connected.");
	// Wait for connected
	nng_aio_wait(aio_connected);
	rv = nng_aio_result(aio_connected);
	assert(rv == 0);

	// Send a disconnect msg and let peer to close this connection
	nng_msg *disconnmsg = disconnect_msg();
	assert(disconnmsg != NULL);
	assert(0 == nng_sendmsg(sock, disconnmsg, NNG_FLAG_ALLOC));

	printf("waiting for disconnected.");
	// Wait for disconnected
	nng_aio_wait(aio_disconnected);
	rv = nng_aio_result(aio_disconnected);
	assert(rv == 0);

	conn_param *cparam = nng_msg_get_conn_param(connmsg);
	nng_close(sock);

	conn_param_free(cparam);
	nng_aio_free(aio_connected);
	nng_aio_free(aio_disconnected);
	printf("...done.\n");
}

void
echo_loop(int id, int ver, nng_msg *(*pubmsg)())
{
	int rv;
	nng_dialer dialer;
	nng_socket sock;
	nng_msg   *connmsg;
	char       buf[64];

	if (ver == 4)
		rv = nng_mqtt_quic_client_open(&sock);
	else if (ver == 5)
		rv = nng_mqttv5_quic_client_open(&sock);
	else {
		printf("Unsupported version.\n");
		return;
	}

	assert(rv == 0);

	rv = nng_dialer_create(&dialer, sock, TEST_MQTT_QUIC_URL);
	assert(rv == 0);

	sprintf(buf, "nanomq-quic-smoke-test3-%d", id);
	connmsg = connect_msg(ver, buf);
	assert(connmsg != NULL);
	nng_dialer_set_ptr(dialer, NNG_OPT_MQTT_CONNMSG, connmsg);

	nng_aio *aio_connected;
	nng_aio_alloc(&aio_connected, NULL, NULL);
	assert(aio_connected != NULL);
	if (ver == 4)
		rv = nng_mqtt_quic_set_connect_cb(&sock, connect_cb, (void *)aio_connected);
	else if (ver == 5)
		rv = nng_mqttv5_quic_set_connect_cb(&sock, connect_cb, (void *)aio_connected);
	assert(rv == 0);

	nng_aio *aio_disconnected;
	nng_aio_alloc(&aio_disconnected, NULL, NULL);
	assert(aio_disconnected != NULL);
	if (ver == 4)
		rv = nng_mqtt_quic_set_disconnect_cb(&sock, disconnect_cb, (void *)aio_disconnected);
	else if (ver == 5)
		rv = nng_mqttv5_quic_set_disconnect_cb(&sock, disconnect_cb, (void *)aio_disconnected);
	assert(rv == 0);

	assert(true == nng_aio_begin(aio_connected));
	assert(true == nng_aio_begin(aio_disconnected));

	rv = nng_dialer_start(dialer, NNG_FLAG_ALLOC);
	assert(rv == 0 || rv == SERVER_UNAVAILABLE);
	if (rv == SERVER_UNAVAILABLE) {
		printf("[Server Unavailable] so...done\n");
		return;
	}

	printf("waiting for connected.");
	// Wait for connected
	nng_aio_wait(aio_connected);
	rv = nng_aio_result(aio_connected);
	assert(rv == 0);

	// Start to subscribe
	nng_aio *aio_ack;
	nng_aio_alloc(&aio_ack, NULL, NULL);
	assert(aio_ack != NULL);

	nng_msg *submsg = subscribe_msg();
	assert(submsg != NULL);
	nng_aio_set_msg(aio_ack, submsg);
	nng_send_aio(sock, aio_ack);
	nng_aio_wait(aio_ack);
	assert(0 == nng_aio_result(aio_ack));
	nng_msg *ackmsg = nng_aio_get_msg(aio_ack);
	assert(ackmsg != NULL);
	nng_msg_free(ackmsg);

	conn_param *cparam = nng_msg_get_conn_param(connmsg);

	for (int i=0; i<10; ++i) {
		printf("Echo round %d...\n", i);
		nng_msg *smsg = pubmsg();
		assert(smsg != NULL);
		nng_aio_set_msg(aio_ack, smsg);
		nng_send_aio(sock, aio_ack);
		nng_aio_wait(aio_ack);
		rv = nng_aio_result(aio_ack);
		assert(0 == rv);

		nng_msg *rmsg = NULL;
		rv = nng_recvmsg(sock, &rmsg, NNG_FLAG_ALLOC);

		uint8_t type = nng_mqtt_msg_get_packet_type(rmsg);
		// For the compatibility of nanomq bridge. Free conn_param
		if (NNG_MQTT_PUBLISH == type)
			conn_param_free(cparam);

		assert(0 == rv);
		assert(rmsg != NULL);
		nng_msg_free(rmsg);
	}

	// Close connection actively
	nng_close(sock);

	printf("waiting for disconnected.");
	// Wait for disconnected
	nng_aio_wait(aio_disconnected);
	rv = nng_aio_result(aio_disconnected);
	assert(rv == 0);

	conn_param_free(cparam);
	nng_aio_free(aio_ack);
	nng_aio_free(aio_connected);
	nng_aio_free(aio_disconnected);
	printf("...done.\n");
}

int
main()
{
	/*
	// Debug with log enabled
	conf_log log;
	log.level = NNG_LOG_DEBUG;
	log.type = LOG_TO_CONSOLE;
	log_init(&log);
	*/

	for (int i=0; i<TEST_ROUND_COUNTER; ++i) {
		printf("%s v4 (%d): ", "con_dis_self", i);
		con_dis_self(i, 4); // mqttv4
	}
	for (int i=0; i<TEST_ROUND_COUNTER; ++i) {
		printf("%s v5 (%d): ", "con_dis_self", i);
		con_dis_self(i, 5); // mqttv5
	}

	for (int i=0; i<TEST_ROUND_COUNTER; ++i) {
		printf("%s v4 (%d): ", "con_dis_peer", i);
		con_dis_peer(i, 4); // mqttv4
	}
	for (int i=0; i<TEST_ROUND_COUNTER; ++i) {
		printf("%s v5 (%d): ", "con_dis_peer", i);
		con_dis_peer(i, 5); // mqttv5
	}

	for (int i=0; i<TEST_ROUND_COUNTER; ++i) {
		printf("%s v4 (%d): ", "echo_loop", i);
		echo_loop(i, 4, publish_msg); // mqttv4
	}
	for (int i=0; i<TEST_ROUND_COUNTER; ++i) {
		printf("%s v5 (%d): ", "echo_loop", i);
		echo_loop(i, 5, publish_msg); // mqttv5
	}

	for (int i=0; i<TEST_ROUND_COUNTER/10; ++i) {
		printf("%s v4 (%d): ", "echo_large_loop", i);
		echo_loop(i, 4, publish_large_msg); // mqttv4
	}
	for (int i=0; i<TEST_ROUND_COUNTER/10; ++i) {
		printf("%s v5 (%d): ", "echo_large_loop", i);
		echo_loop(i, 5, publish_large_msg); // mqttv5
	}

	return 0;
}
