// Check the actual MQTT wire headers, including broker retransmissions.
#include "include/broker.h"
#include "tests_api.h"
#include <nng/supplemental/nanolib/file.h>

typedef struct {
	nng_stream        *stream;
	nng_stream_dialer *dialer;
	nng_aio           *aio;
} wire_client;

static void
wire_io(wire_client *client, void *buf, size_t len, bool send)
{
	while (len > 0) {
		nng_iov iov = { buf, len };
		assert(nng_aio_set_iov(client->aio, 1, &iov) == 0);
		if (send) {
			nng_stream_send(client->stream, client->aio);
		} else {
			nng_stream_recv(client->stream, client->aio);
		}
		nng_aio_wait(client->aio);
		assert(nng_aio_result(client->aio) == 0);
		size_t count = nng_aio_count(client->aio);
		assert(count > 0 && count <= len);
		buf = (uint8_t *) buf + count;
		len -= count;
	}
}

// Test packets deliberately fit in a one-byte Remaining Length field.
static void
wire_send(wire_client *client, uint8_t header, const uint8_t *body, size_t len)
{
	uint8_t packet[128];
	assert(len < sizeof(packet) - 2);
	packet[0] = header;
	packet[1] = (uint8_t) len;
	memcpy(packet + 2, body, len);
	wire_io(client, packet, len + 2, true);
}

static size_t
wire_recv(wire_client *client, uint8_t *header, uint8_t *body)
{
	uint8_t len;
	wire_io(client, header, 1, false);
	wire_io(client, &len, 1, false);
	assert(len < 128);
	wire_io(client, body, len, false);
	return len;
}

static void
expect_ack(wire_client *client, uint8_t expected, uint16_t pid)
{
	uint8_t header, body[128];
	size_t  len = wire_recv(client, &header, body);
	assert(header == expected && len >= 2);
	assert(body[0] == (pid >> 8) && body[1] == (pid & 0xff));
}

static void
wire_open(wire_client *client, const char *url, uint8_t version, char id)
{
	uint8_t header, body[128];
	uint8_t connect[] = {
		0, 4, 'M', 'Q', 'T', 'T', version, 2, 0, 60,
		0, 0, 1, (uint8_t) id
	};
	assert(nng_aio_alloc(&client->aio, NULL, NULL) == 0);
	nng_aio_set_timeout(client->aio, 5000);
	assert(nng_stream_dialer_alloc(&client->dialer, url) == 0);
	if (strstr(url, "ws") != NULL) {
		assert(nng_stream_dialer_set_string(
		    client->dialer, NNG_OPT_WS_PROTOCOL, "mqtt") == 0);
	}
#ifdef NNG_SUPP_TLS
	if (strstr(url, "tls+") != NULL || strstr(url, "wss:") != NULL) {
		assert(nng_stream_dialer_set_int(client->dialer,
		    NNG_OPT_TLS_AUTH_MODE, NNG_TLS_AUTH_MODE_NONE) == 0);
	}
#endif
	nng_stream_dialer_dial(client->dialer, client->aio);
	nng_aio_wait(client->aio);
	assert(nng_aio_result(client->aio) == 0);
	client->stream = nng_aio_get_output(client->aio, 0);
	if (version == 4) {
		memmove(connect + 10, connect + 11, 3);
	}
	wire_send(client, 0x10, connect, version == 5 ? 14 : 13);
	assert(wire_recv(client, &header, body) >= 2);
	assert(header == 0x20 && body[1] == 0);
}

static void
wire_close(wire_client *client)
{
	nng_stream_close(client->stream);
	nng_stream_free(client->stream);
	nng_stream_dialer_free(client->dialer);
	nng_aio_free(client->aio);
}

static void
subscribe(wire_client *client, uint8_t version, uint8_t qos)
{
	uint8_t body[] = { 0, 1, 0, 0, 3, 'd', 'u', 'p', qos };
	if (version == 4) {
		memmove(body + 2, body + 3, 6);
	}
	wire_send(client, 0x82, body, version == 5 ? 9 : 8);
	uint8_t header, reply[128];
	size_t len = wire_recv(client, &header, reply);
	assert(header == 0x90 && len == (version == 5 ? 4 : 3));
	assert(reply[0] == 0 && reply[1] == 1 && reply[len - 1] == qos);
}

static void
publish(wire_client *client, uint8_t version, uint8_t qos, bool dup)
{
	uint8_t body[16] = { 0, 3, 'd', 'u', 'p' };
	size_t  len = 5;
	if (qos > 0) {
		body[len++] = 0;
		body[len++] = 7;
	}
	if (version == 5) {
		body[len++] = 0; // Property Length
	}
	body[len++] = 'o';
	body[len++] = 'k';
	wire_send(client, 0x30 | (qos << 1) | (dup ? 8 : 0), body, len);
	if (qos > 0) {
		expect_ack(client, qos == 1 ? 0x40 : 0x50, 7);
	}
	if (qos == 2) {
		uint8_t pid[] = { 0, 7 };
		wire_send(client, 0x62, pid, sizeof(pid));
		expect_ack(client, 0x70, 7);
	}
}

static uint16_t
expect_publish(wire_client *client, uint8_t version, uint8_t qos, bool dup)
{
	uint8_t header, body[128];
	size_t  len = wire_recv(client, &header, body);
	uint8_t expected = 0x30 | (qos << 1) | (dup ? 8 : 0);
	if (header != expected) {
		fprintf(stderr, "PUBLISH: expected 0x%02x, received 0x%02x\n",
		    expected, header);
	}
	assert(header == expected);
	assert(len == 7 + (qos > 0 ? 2 : 0) + (version == 5 ? 1 : 0));
	assert(memcmp(body, "\0\3dup", 5) == 0);
	size_t   pos = 5;
	uint16_t pid = 0;
	if (qos > 0) {
		pid = ((uint16_t) body[pos] << 8) | body[pos + 1];
		pos += 2;
		assert(pid != 0);
	}
	if (version == 5) {
		assert(body[pos++] == 0);
	}
	assert(memcmp(body + pos, "ok", 2) == 0);
	return pid;
}

static void
ack_publish(wire_client *client, uint8_t qos, uint16_t pid)
{
	uint8_t body[] = { (uint8_t) (pid >> 8), (uint8_t) pid };
	if (qos > 0) {
		wire_send(client, qos == 1 ? 0x40 : 0x50, body, sizeof(body));
	}
	if (qos == 2) {
		expect_ack(client, 0x62, pid);
		wire_send(client, 0x70, body, sizeof(body));
	}
}

static void
test_forward(const char *puburl, const char *url, uint8_t pubver, uint8_t subver)
{
	wire_client pub, sub[3];
	wire_open(&pub, puburl, pubver, 'p');
	for (uint8_t qos = 0; qos < 3; qos++) {
		wire_open(&sub[qos], url, subver, '0' + qos);
		subscribe(&sub[qos], subver, qos);
	}
	for (uint8_t qos = 0; qos < 3; qos++) {
		for (int dup = 0; dup <= (qos > 0 ? 1 : 0); dup++) {
			printf("%s MQTT %u -> %u, publish QoS %u DUP %d\n",
			    url, pubver, subver, qos, dup);
			publish(&pub, pubver, qos, dup);
			for (uint8_t sqos = 0; sqos < 3; sqos++) {
				uint8_t out_qos = qos < sqos ? qos : sqos;
				uint16_t pid = expect_publish(
				    &sub[sqos], subver, out_qos, false);
				ack_publish(&sub[sqos], out_qos, pid);
			}
		}
	}
	for (int i = 0; i < 3; i++) {
		wire_close(&sub[i]);
	}
	wire_close(&pub);
}

static void
test_retry(const char *puburl, const char *url, uint8_t version)
{
	wire_client pub, sub;
	wire_open(&pub, puburl, version, 'p');
	wire_open(&sub, url, version, 's');
	subscribe(&sub, version, 1);
	publish(&pub, version, 1, false);
	uint16_t pid = expect_publish(&sub, version, 1, false);
	// Withhold PUBACK: the broker must set DUP and reuse its packet ID.
	assert(expect_publish(&sub, version, 1, true) == pid);
	ack_publish(&sub, 1, pid);
	wire_close(&sub);
	wire_close(&pub);
}

static void
test_overlapping_retry(const char *puburl, const char *url, uint8_t version)
{
	wire_client pub, sub;
	wire_open(&pub, puburl, version, 'p');
	wire_open(&sub, url, version, 's');
	// The two QoS 0 deliveries fill the first IOV batch. The QoS 1
	// delivery is continued by the TCP/TLS send callback.
	uint8_t body[] = { 0, 2, 0,
		0, 3, 'd', 'u', 'p', 0,
		0, 1, '+', 0,
		0, 1, '#', 1 };
	if (version == 4) {
		memmove(body + 2, body + 3, sizeof(body) - 3);
	}
	wire_send(&sub, 0x82, body, sizeof(body) - (version == 4 ? 1 : 0));
	uint8_t header, reply[128];
	size_t len = wire_recv(&sub, &header, reply);
	assert(header == 0x90 && len == (version == 5 ? 6 : 5));
	assert(memcmp(reply + len - 3, "\0\0\1", 3) == 0);
	publish(&pub, version, 1, false);
	expect_publish(&sub, version, 0, false);
	expect_publish(&sub, version, 0, false);
	uint16_t pid = expect_publish(&sub, version, 1, false);
	expect_publish(&sub, version, 0, false);
	expect_publish(&sub, version, 0, false);
	assert(expect_publish(&sub, version, 1, true) == pid);
	ack_publish(&sub, 1, pid);
	wire_close(&sub);
	wire_close(&pub);
}

int
main(void)
{
	if (!test_env_allows_network_binds()) {
		fprintf(stderr, "skip: listening sockets unavailable\n");
		return 77;
	}
	const char *schemes[] = {
		"tcp", "ws",
#ifdef NNG_SUPP_TLS
		"tls+tcp", "wss",
#endif
	};
	const char *broker_schemes[] = { "nmq-tcp", "nmq-ws",
		"tls+nmq-tcp", "nmq-wss" };
	char urls[4][80], broker_urls[4][80];
	uint16_t ports[4];
	nng_stream_listener *reserved[4];
	size_t transports = sizeof(schemes) / sizeof(schemes[0]);
	// Reserve distinct ephemeral ports until all listener URLs are ready.
	for (size_t i = 0; i < transports; i++) {
		nng_sockaddr addr;
		assert(nng_stream_listener_alloc(
		    &reserved[i], "tcp://127.0.0.1:0") == 0);
		assert(nng_stream_listener_listen(reserved[i]) == 0);
		assert(nng_stream_listener_get_addr(
		    reserved[i], NNG_OPT_LOCADDR, &addr) == 0);
		uint8_t *port = (void *) &addr.s_in.sa_port;
		ports[i] = ((uint16_t) port[0] << 8) | port[1];
		const char *path = i % 2 ? "/mqtt" : "";
		snprintf(urls[i], sizeof(urls[i]), "%s://127.0.0.1:%u%s",
		    schemes[i], ports[i], path);
		snprintf(broker_urls[i], sizeof(broker_urls[i]),
		    "%s://127.0.0.1:%u%s", broker_schemes[i], ports[i], path);
	}
	conf *cfg = nng_zalloc(sizeof(*cfg));
	assert(cfg != NULL);
	conf_init(cfg);
	cfg->url = nng_strdup(broker_urls[0]);
	cfg->parallel = 4;
	cfg->qos_duration = 1;
	cfg->websocket.enable = true;
	cfg->websocket.url = nng_strdup(broker_urls[1]);
#ifdef NNG_SUPP_TLS
	cfg->tls.enable = true;
	cfg->tls.url = nng_strdup(broker_urls[2]);
	file_load_data(NANOMQ_TEST_CERT_DIR "/cert.pem", (void **) &cfg->tls.cert);
	file_load_data(NANOMQ_TEST_CERT_DIR "/key.pem", (void **) &cfg->tls.key);
	assert(cfg->tls.cert != NULL && cfg->tls.key != NULL);
	cfg->websocket.tls_enable = true;
	cfg->websocket.tls_url = nng_strdup(broker_urls[3]);
#endif
	for (size_t i = 0; i < transports; i++) {
		nng_stream_listener_free(reserved[i]);
	}
	nng_thread *broker;
	assert(nng_thread_create(
	    &broker, (void *) broker_start_with_conf, cfg) == 0);
	for (size_t i = 0; i < transports; i++) {
		assert(test_env_wait_for_tcp_listener(ports[i], 5000));
	}
	for (size_t i = 0; i < transports; i++) {
		for (uint8_t pubver = 4; pubver <= 5; pubver++) {
			for (uint8_t subver = 4; subver <= 5; subver++) {
				test_forward(urls[0], urls[i], pubver, subver);
			}
			test_retry(urls[0], urls[i], pubver);
			if (i % 2 == 0) {
				test_overlapping_retry(urls[0], urls[i], pubver);
			}
		}
	}
	broker_stop_for_test();
	nng_thread_destroy(broker);
	return 0;
}
