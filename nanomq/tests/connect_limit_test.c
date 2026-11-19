// CONNECT negotiation must enforce the receive limit before allocating its body.
#include <nng/nng.h>
#include <nng/protocol/mqtt/mqtt_parser.h>
#include <nng/protocol/mqtt/nmq_mqtt.h>
#ifdef NNG_SUPP_TLS
#include <nng/supplemental/nanolib/file.h>
#include <nng/supplemental/tls/tls.h>
#endif

#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <string.h>

#ifdef CONNECT_FAULT_INJECTION
#include <stdatomic.h>

static atomic_size_t fail_alloc_size;
static atomic_size_t fail_append_size;
static atomic_bool fail_conn_param;
static atomic_int failed_allocs;

void *__real_nng_alloc(size_t);
int __real_nni_msg_append(nng_msg *, const void *, size_t);
int __real_conn_param_alloc(conn_param **);

int
__wrap_conn_param_alloc(conn_param **param)
{
	if (atomic_exchange(&fail_conn_param, false)) {
		atomic_fetch_add(&failed_allocs, 1);
		return NNG_ENOMEM;
	}
	return __real_conn_param_alloc(param);
}

void *
__wrap_nng_alloc(size_t size)
{
	size_t expected = size;
	if (size != 0 && atomic_compare_exchange_strong(
	        &fail_alloc_size, &expected, 0)) {
		atomic_fetch_add(&failed_allocs, 1);
		return NULL;
	}
	return __real_nng_alloc(size);
}

int
__wrap_nni_msg_append(nng_msg *msg, const void *data, size_t size)
{
	size_t expected = size;
	if (size != 0 && atomic_compare_exchange_strong(
	        &fail_append_size, &expected, 0)) {
		atomic_fetch_add(&failed_allocs, 1);
		return NNG_ENOMEM;
	}
	return __real_nni_msg_append(msg, data, size);
}
#endif

static void
wire_io(nng_stream *stream, nng_aio *aio, void *buf, size_t len, bool send)
{
	while (len > 0) {
		nng_iov iov = { buf, len };
		assert(nng_aio_set_iov(aio, 1, &iov) == 0);
		if (send) {
			nng_stream_send(stream, aio);
		} else {
			nng_stream_recv(stream, aio);
		}
		nng_aio_wait(aio);
		assert(nng_aio_result(aio) == 0);
		size_t count = nng_aio_count(aio);
		assert(count > 0 && count <= len);
		buf = (uint8_t *) buf + count;
		len -= count;
	}
}

static nng_stream *
open_stream(nng_stream_dialer *dialer, nng_aio *aio)
{
	nng_stream_dialer_dial(dialer, aio);
	nng_aio_wait(aio);
	assert(nng_aio_result(aio) == 0);
	return nng_aio_get_output(aio, 0);
}

static void
send_connect(nng_stream *stream, nng_aio *aio, uint8_t *packet,
    size_t len, bool split)
{
	if (split) {
		wire_io(stream, aio, packet++, 1, true);
		len--;
	}
	wire_io(stream, aio, packet, len, true);
}

static void
expect_closed(nng_stream *stream, nng_aio *aio)
{
	uint8_t reply[8];
	nng_iov iov = { reply, sizeof(reply) };
	assert(nng_aio_set_iov(aio, 1, &iov) == 0);
	nng_stream_recv(stream, aio);
	nng_aio_wait(aio);
	int rv = nng_aio_result(aio);
	// The mbedTLS backend maps peer close_notify to NNG_ECONNREFUSED.
	if (rv != NNG_ECLOSED && rv != NNG_ECONNSHUT &&
	    rv != NNG_ECONNRESET && rv != NNG_ECONNREFUSED) {
		fprintf(stderr, "packet was not rejected: %s\n",
		    nng_strerror(rv));
		assert(false);
	}
	nng_stream_free(stream);
}

static void
reject_connect(nng_stream_dialer *dialer, nng_aio *aio,
    uint8_t *packet, size_t len, bool split)
{
	nng_stream *stream = open_stream(dialer, aio);
	send_connect(stream, aio, packet, len, split);
	expect_closed(stream, aio);
}

static void
check_session(nng_socket sock, nng_stream_dialer *dialer, nng_aio *aio,
    uint8_t version, size_t remaining, bool split, bool ws)
{
	nng_stream *stream = open_stream(dialer, aio);
	uint8_t packet[66] = {
		0x10, (uint8_t) remaining, 0, 4, 'M', 'Q', 'T', 'T',
		version, 2, 0, 60
	};
	assert(remaining >= (version == 5 ? 14 : 13) && remaining <= 64);
	size_t pos = 12;
	if (version == 5) {
		packet[pos++] = 0; // CONNECT Property Length.
	}
	size_t id_len = remaining - pos;
	packet[pos++] = 0;
	packet[pos++] = (uint8_t) id_len;
	memset(packet + pos, '0' + version, id_len);
	assert(pos + id_len == remaining + 2);
	send_connect(stream, aio, packet, remaining + 2, split);

	// Mirror the application's CONNACK send and AIO completion in broker.c.
	nng_msg *msg;
	assert(nng_recvmsg(sock, &msg, 0) == 0);
	assert(nng_msg_cmd_type(msg) == CMD_CONNACK);
	conn_param *cparam = nng_msg_get_conn_param(msg);
	nng_pipe pipe = nng_msg_get_pipe(msg);
	nng_aio *send;
	assert(nng_aio_alloc(&send, NULL, NULL) == 0);
	nng_aio_set_prov_data(send, &pipe.id);
	nng_aio_set_msg(send, msg);
	nng_send_aio(sock, send);
	assert(nng_aio_get_msg(send) == NULL);
	nng_aio_finish(send, 0);
	nng_aio_wait(send);
	nng_aio_free(send);
	conn_param_free(cparam);
	uint8_t reply[128];
	wire_io(stream, aio, reply, 2, false);
	assert(reply[0] == 0x20 && reply[1] >= 2 && reply[1] < sizeof(reply) - 2);
	wire_io(stream, aio, reply + 2, reply[1], false);
	assert(reply[3] == 0);

	// A normal PUBLISH exactly at the cap also exercises the established
	// receive path. Use a one-byte topic and fill the remainder with payload.
	uint8_t publish[64] = { 0x30, 62, 0, 1, 't' };
	size_t payload = 5;
	if (version == 5) {
		publish[payload++] = 0; // Property Length.
	}
	memset(publish + payload, 'x', sizeof(publish) - payload);
	// One WebSocket message may contain multiple MQTT packets. Its total
	// size may exceed the MQTT limit as long as each packet fits.
	bool batch = ws && !split;
	if (batch) {
		uint8_t pair[2 * sizeof(publish)];
		memcpy(pair, publish, sizeof(publish));
		memcpy(pair + sizeof(publish), publish, sizeof(publish));
		wire_io(stream, aio, pair, sizeof(pair), true);
	} else {
		wire_io(stream, aio, publish, sizeof(publish), true);
	}
	for (int i = 0; i < (batch ? 2 : 1); i++) {
		assert(nng_recvmsg(sock, &msg, 0) == 0);
		assert(nng_msg_cmd_type(msg) == CMD_PUBLISH);
		assert(nng_msg_len(msg) + nng_msg_header_len(msg) == sizeof(publish));
		assert(nng_msg_len(msg) == sizeof(publish) - 2);
		assert(memcmp(nng_msg_body(msg), publish + 2, sizeof(publish) - 2) == 0);
		conn_param_free(nng_msg_get_conn_param(msg));
		nng_msg_free(msg);
	}

	// Only the fixed header is needed to reject a PUBLISH one byte over
	// the cap. This also covers the established receive path's size check.
	uint8_t over_publish[] = { 0x30, 63 };
	if (batch) {
		// Also check a later packet in the batch: a valid PINGREQ followed
		// by an oversized PUBLISH header must fail before reading its body.
		uint8_t over_batch[] = { 0xc0, 0, 0x30, 63 };
		wire_io(stream, aio, over_batch, sizeof(over_batch), true);
	} else {
		wire_io(stream, aio, over_publish, sizeof(over_publish), true);
	}
	assert(nng_recvmsg(sock, &msg, 0) == 0);
	assert(nng_msg_cmd_type(msg) == CMD_DISCONNECT_EV);
	// The protocol may send a v5 DISCONNECT before closing the connection.
	nng_stream_close(stream);
	nng_stream_free(stream);
	// Release the session reference and the notification clone, as broker.c does.
	cparam = nng_msg_get_conn_param(msg);
	conn_param_free(cparam);
	conn_param_free(cparam);
	nng_msg_free(msg);
}

#ifdef CONNECT_FAULT_INJECTION
static void
check_alloc_failures(nng_socket sock, nng_stream_dialer *dialer,
    nng_aio *aio, bool ws)
{
	uint8_t connect[] = {
		0x10, 13, 0, 4, 'M', 'Q', 'T', 'T', 4, 2, 0, 60, 0, 1, 'f'
	};
	if (!ws) {
		// In-range CONNECT: fail its body buffer allocation before any body
		// arrives. The listener must remain usable after this failure.
		nng_stream *stream = open_stream(dialer, aio);
		int before = atomic_load(&failed_allocs);
		atomic_store(&fail_alloc_size, sizeof(connect));
		wire_io(stream, aio, connect, 5, true);
		expect_closed(stream, aio);
		assert(atomic_load(&failed_allocs) == before + 1);
		assert(atomic_load(&fail_alloc_size) == 0);
		check_session(sock, dialer, aio, 4, 13, false, ws);
	}
	// Fail CONNECT parameter allocation after receiving the entire body.
	// ASan/LSan checks that both the buffer and the rejected pipe are freed.
	nng_stream *stream = open_stream(dialer, aio);
	int before = atomic_load(&failed_allocs);
	atomic_store(&fail_conn_param, true);
	wire_io(stream, aio, connect, sizeof(connect), true);
	expect_closed(stream, aio);
	assert(atomic_load(&failed_allocs) == before + 1);
	assert(!atomic_load(&fail_conn_param));
	check_session(sock, dialer, aio, 5, 14, true, ws);
	if (ws) {
		// A second WS message grows the buffered CONNECT. Fail that append.
		stream = open_stream(dialer, aio);
		before = atomic_load(&failed_allocs);
		atomic_store(&fail_append_size, sizeof(connect) - 1);
		send_connect(stream, aio, connect, sizeof(connect), true);
		expect_closed(stream, aio);
		assert(atomic_load(&failed_allocs) == before + 1);
		assert(atomic_load(&fail_append_size) == 0);
		check_session(sock, dialer, aio, 4, 13, false, ws);
	}
}
#endif

static int
check_transport(bool tls, bool ws)
{
	conf *cfg = nng_zalloc(sizeof(*cfg));
	assert(cfg != NULL);
	conf_init(cfg);
	// The limit covers the fixed header as well as Remaining Length.
	cfg->max_packet_size = 64;
	nng_socket sock = { .data = cfg };
	nng_listener listener;
	assert(nng_nmq_tcp0_open(&sock) == 0);
	assert(nng_socket_set_ms(sock, NNG_OPT_RECVTIMEO, 5000) == 0);
	const char *listen_url = ws
	    ? (tls ? "nmq-wss://127.0.0.1:0/mqtt" : "nmq-ws://127.0.0.1:0/mqtt")
	    : (tls ? "tls+nmq-tcp://127.0.0.1:0" : "nmq-tcp://127.0.0.1:0");
	assert(nng_listener_create(&listener, sock, listen_url) == 0);
	assert(nng_listener_set(listener, NANO_CONF, cfg, sizeof(*cfg)) == 0);
#ifdef NNG_SUPP_TLS
	if (tls) {
		file_load_data(NANOMQ_TEST_CERT_DIR "/cert.pem", (void **) &cfg->tls.cert);
		file_load_data(NANOMQ_TEST_CERT_DIR "/key.pem", (void **) &cfg->tls.key);
		assert(cfg->tls.cert != NULL && cfg->tls.key != NULL);
		nng_tls_config *tc;
		assert(nng_tls_config_alloc(&tc, NNG_TLS_MODE_SERVER) == 0);
		assert(nng_tls_config_auth_mode(tc, NNG_TLS_AUTH_MODE_NONE) == 0);
		assert(nng_tls_config_own_cert(tc, cfg->tls.cert, cfg->tls.key, NULL) == 0);
		assert(nng_listener_set_ptr(listener, NNG_OPT_TLS_CONFIG, tc) == 0);
		nng_tls_config_free(tc);
	}
#endif
	int rv = nng_listener_start(listener, 0);
	if (rv == NNG_EPERM || rv == NNG_ENOTSUP) {
		nng_close(sock);
		fprintf(stderr, "skip: listening sockets unavailable\n");
		return 77;
	}
	assert(rv == 0);
	nng_sockaddr addr;
	assert(nng_listener_get_addr(listener, NNG_OPT_LOCADDR, &addr) == 0);
	uint8_t *port = (void *) &addr.s_in.sa_port;
	char url[80];
	snprintf(url, sizeof(url), "%s://127.0.0.1:%u%s",
	    ws ? (tls ? "wss" : "ws") : (tls ? "tls+tcp" : "tcp"),
	    ((unsigned) port[0] << 8) | port[1], ws ? "/mqtt" : "");
	nng_stream_dialer *dialer;
	nng_aio *aio;
	assert(nng_stream_dialer_alloc(&dialer, url) == 0);
	if (ws) {
		assert(nng_stream_dialer_set_string(
		    dialer, NNG_OPT_WS_PROTOCOL, "mqtt") == 0);
	}
#ifdef NNG_SUPP_TLS
	if (tls) {
		assert(nng_stream_dialer_set_int(dialer,
		    NNG_OPT_TLS_AUTH_MODE, NNG_TLS_AUTH_MODE_NONE) == 0);
	}
#endif
	assert(nng_aio_alloc(&aio, NULL, NULL) == 0);
	// A rejected prefix must close before the transport's 15-second timeout.
	nng_aio_set_timeout(aio, 3000);
	uint8_t over_one[] = { 0x10, 63, 0, 4, 'M' }; // 65 total bytes.
	uint8_t over_two[] = { 0x10, 0x80, 1, 0, 4 }; // Remaining Length 128.
	for (uint8_t version = 4; version <= 5; version++) {
		// RL 62 plus the two-byte fixed header is exactly the 64-byte limit.
		check_session(sock, dialer, aio, version, 62, version == 5, ws);
		reject_connect(dialer, aio, over_one, sizeof(over_one), version == 5);
		// Short valid CONNECT: RL 13 for v4, RL 14 for v5; one-byte client ID.
		check_session(sock, dialer, aio, version,
		    version == 5 ? 14 : 13, false, ws);
		reject_connect(dialer, aio, over_two, sizeof(over_two), version == 4);
		check_session(sock, dialer, aio, version,
		    version == 5 ? 14 : 13, true, ws);
	}
	// No payload or credentials: the maximum legal Remaining Length alone
	// must close the connection, without waiting for the negotiation timeout.
	uint8_t maximum[] = { 0x10, 0xff, 0xff, 0xff, 0x7f };
	uint8_t malformed[] = { 0x10, 0xff, 0xff, 0xff, 0xff };
#ifdef CONNECT_FAULT_INJECTION
	int before = atomic_load(&failed_allocs);
	atomic_store(&fail_alloc_size, 268435455u + sizeof(maximum));
#endif
	reject_connect(dialer, aio, maximum, sizeof(maximum), false);
	// Split all four Remaining Length bytes across separate sends.
	nng_stream *stream = open_stream(dialer, aio);
	for (size_t i = 0; i < sizeof(maximum); i++) {
		wire_io(stream, aio, maximum + i, 1, true);
	}
	expect_closed(stream, aio);
#ifdef CONNECT_FAULT_INJECTION
	// Oversized CONNECT must never reach its declared buffer allocation.
	assert(atomic_load(&failed_allocs) == before);
	assert(atomic_exchange(&fail_alloc_size, 0) ==
	    268435455u + sizeof(maximum));
#endif
	reject_connect(dialer, aio, malformed, sizeof(malformed), true);
	if (ws) {
		// A complete WS message and accumulated fragments are both capped
		// before copying. The declared CONNECT itself fits the configured cap.
		uint8_t excess[65] = { 0x10, 62, 0, 4, 'M' };
		reject_connect(dialer, aio, excess, sizeof(excess), false);
		reject_connect(dialer, aio, excess, sizeof(excess), true);
		// WS can reject a one-byte Remaining Length after just two bytes.
		reject_connect(dialer, aio, over_one, 2, false);
	}
	check_session(sock, dialer, aio, 5, 14, true, ws);
#ifdef CONNECT_FAULT_INJECTION
	check_alloc_failures(sock, dialer, aio, ws);
#endif
	nng_aio_free(aio);
	nng_stream_dialer_free(dialer);
	assert(nng_close(sock) == 0); // The socket owns cfg.
	return 0;
}

int
main(void)
{
	int rv = check_transport(false, false);
#ifdef NNG_SUPP_TLS
	if (rv == 0) {
		rv = check_transport(true, false);
	}
#endif
#ifdef NANO_TEST_WS
	if (rv == 0) {
		rv = check_transport(false, true);
	}
#endif
#ifdef NANO_TEST_WSS
	if (rv == 0) {
		rv = check_transport(true, true);
	}
#endif
	nng_fini();
	return rv;
}
