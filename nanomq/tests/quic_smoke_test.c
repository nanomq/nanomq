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
#include <assert.h>

#include <nng/mqtt/mqtt_quic_client.h>
#include <nng/mqtt/mqtt_client.h>

#define TEST_MQTT_QUIC_URL "mqtt-quic://us.432121.xyz:14567"

nng_msg *
connect_msg(uint8_t ver, char *client_id)
{
	nng_msg *msg;
	nng_mqtt_msg_alloc(&msg, 0);
	nng_mqtt_msg_set_packet_type(msg, NNG_MQTT_CONNECT);
	nng_mqtt_msg_set_connect_proto_version(msg, ver);
	nng_mqtt_msg_set_connect_keep_alive(msg, 60);
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
	printf("Connected cb, rv %d.\n", rv);
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

	sprintf(buf, "nanomq-quic-smoke-test-clientid-%d", id);
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

	rv = nng_dialer_start(dialer, NNG_FLAG_ALLOC);
	assert(rv == 0);

	// Wait for connected
	nng_aio_wait(aio_connected);
	rv = nng_aio_result(aio_connected);
	assert(rv == 0);

	// Wait for disconnected
	nng_aio_wait(aio_disconnected);
	rv = nng_aio_result(aio_disconnected);
	assert(rv == 0);

	// Disconnect actively
	conn_param *cparam = nng_msg_get_conn_param(connmsg);
	nng_close(sock);
	conn_param_free(cparam);
	nng_aio_free(aio_connected);
	nng_aio_free(aio_disconnected);
	printf("...done.\n");
}

int
main()
{
	for (int i=0; i<100; ++i) {
		printf("No.%d. ", i);
		con_dis_self(i);
		nng_msleep(100);
	}
	return 0;
}
