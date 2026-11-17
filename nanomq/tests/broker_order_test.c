//
// Copyright 2026 NanoMQ Team, Inc. <jaylin@emqx.io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

// Ordered-topic regression: independent publisher and subscriber threads.
// Keep assertions active in release builds too.
#undef NDEBUG
#include "include/broker.h"
#include "tests_api.h"


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
wire_open(wire_client *client, const char *url, uint8_t version)
{
	static unsigned next_id;
	char id[32];
	snprintf(id, sizeof(id), "order-client-%u", next_id++);
	uint8_t header, body[128];
	uint8_t connect[64] = { 0, 4, 'M', 'Q', 'T', 'T', version, 2, 0, 60 };
	size_t len = 10;
	if (version == 5) {
		connect[len++] = 0;
	}
	connect[len++] = 0;
	connect[len++] = strlen(id);
	memcpy(connect + len, id, strlen(id));
	len += strlen(id);
	assert(nng_aio_alloc(&client->aio, NULL, NULL) == 0);
	nng_aio_set_timeout(client->aio, 15000);
	assert(nng_stream_dialer_alloc(&client->dialer, url) == 0);
	nng_stream_dialer_dial(client->dialer, client->aio);
	nng_aio_wait(client->aio);
	assert(nng_aio_result(client->aio) == 0);
	client->stream = nng_aio_get_output(client->aio, 0);
	wire_send(client, 0x10, connect, len);
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

#define MESSAGE_COUNT 5000
#define MAX_PUBLISHERS 8

typedef struct {
	wire_client client;
	uint8_t version, qos, id;
	unsigned window, count;
} publisher;

typedef struct {
	wire_client client;
	uint8_t version, qos;
	unsigned publishers, count, inversions;
} subscriber;

static void
publish_sequence(void *arg)
{
	publisher *p = arg;
	for (unsigned start = 0; start < p->count; start += p->window) {
		unsigned end = start + p->window;
		if (end > p->count) {
			end = p->count;
		}
		for (unsigned seq = start; seq < end; seq++) {
			uint16_t pid = seq % 65535 + 1;
			uint8_t body[32] = { 0, 3, 'o', 'r', 'd' };
			size_t len = 5;
			if (p->qos) {
				body[len++] = pid >> 8;
				body[len++] = pid;
			}
			if (p->version == 5) {
				body[len++] = 0;
			}
			body[len++] = p->id;
			body[len++] = seq >> 24;
			body[len++] = seq >> 16;
			body[len++] = seq >> 8;
			body[len++] = seq;
			wire_send(&p->client, 0x30 | (p->qos << 1), body, len);
		}
		if (p->qos) {
			for (unsigned seq = start; seq < end; seq++) {
				expect_ack(&p->client, 0x40, seq % 65535 + 1);
			}
		}
	}
}

static void
receive_sequence(void *arg)
{
	subscriber *s = arg;
	unsigned next[MAX_PUBLISHERS] = { 0 };
	// Detect loss and duplicates independently of delivery order.
	bool *seen = calloc(s->publishers * s->count, sizeof(*seen));
	assert(seen != NULL);
	for (unsigned i = 0; i < s->publishers * s->count; i++) {
		uint8_t header, body[128];
		size_t len = wire_recv(&s->client, &header, body);
		assert(header == (0x30 | (s->qos << 1))); // DUP must be clear.
		assert(len >= 10 && memcmp(body, "\0\3ord", 5) == 0);
		size_t pos = 5;
		if (s->qos) {
			wire_send(&s->client, 0x40, body + pos, 2);
			pos += 2;
		}
		if (s->version == 5) {
			assert(body[pos++] == 0);
		}
		assert(len == pos + 5);
		unsigned id = body[pos++];
		unsigned seq = ((unsigned) body[pos] << 24) |
		    ((unsigned) body[pos + 1] << 16) |
		    ((unsigned) body[pos + 2] << 8) | body[pos + 3];
		assert(id < s->publishers && seq < s->count);
		assert(!seen[id * s->count + seq]);
		seen[id * s->count + seq] = true;
		if (seq != next[id]) {
			s->inversions++;
		}
		next[id] = seq + 1;
	}
	for (unsigned i = 0; i < s->publishers * s->count; i++) {
		assert(seen[i]);
	}
	free(seen);
}

static unsigned
run_order(const char *url, uint8_t version, uint8_t qos, unsigned window,
    unsigned publishers, unsigned count)
{
	subscriber sub = { .version = version, .qos = qos,
		.publishers = publishers, .count = count };
	wire_open(&sub.client, url, version);
	uint8_t body[] = { 0, 1, 0, 0, 3, 'o', 'r', 'd', qos };
	if (version == 4) {
		memmove(body + 2, body + 3, 6);
	}
	wire_send(&sub.client, 0x82, body, version == 5 ? 9 : 8);
	uint8_t header, reply[128];
	assert(wire_recv(&sub.client, &header, reply) >= 3 && header == 0x90);
	assert(reply[version == 5 ? 3 : 2] == qos);
	publisher pubs[MAX_PUBLISHERS];
	nng_thread *threads[MAX_PUBLISHERS], *receiver;
	for (unsigned i = 0; i < publishers; i++) {
		pubs[i] = (publisher) { .version = version, .qos = qos,
			.id = i, .window = window, .count = count };
		wire_open(&pubs[i].client, url, version);
	}
	uint64_t start = nng_clock();
	assert(nng_thread_create(&receiver, receive_sequence, &sub) == 0);
	for (unsigned i = 0; i < publishers; i++) {
		assert(nng_thread_create(&threads[i], publish_sequence, &pubs[i]) == 0);
	}
	for (unsigned i = 0; i < publishers; i++) {
		nng_thread_destroy(threads[i]);
	}
	nng_thread_destroy(receiver);
	printf("%s v%u qos%u window%u publishers%u: %u messages, "
	    "%u order errors, %llu ms\n", url, version, qos, window,
	    publishers, count * publishers, sub.inversions,
	    (unsigned long long) (nng_clock() - start));
	for (unsigned i = 0; i < publishers; i++) {
		wire_close(&pubs[i].client);
	}
	wire_close(&sub.client);
	return sub.inversions;
}

int
main(void)
{
	setvbuf(stdout, NULL, _IOLBF, 0);
	if (!test_env_allows_network_binds()) {
		return 77;
	}
#ifndef NANO_PLATFORM_WINDOWS
	char pid_path[96];
	snprintf(pid_path, sizeof(pid_path), "/tmp/nanomq-order-test-%ld.pid",
	    (long) getpid());
	assert(setenv("NANOMQ_PID_FILE", pid_path, 1) == 0);
#endif
	char url[80], broker_url[80];
	nng_sockaddr addr;
	nng_stream_listener *reserved;
	assert(nng_stream_listener_alloc(&reserved, "tcp://127.0.0.1:0") == 0);
	assert(nng_stream_listener_listen(reserved) == 0);
	assert(nng_stream_listener_get_addr(reserved, NNG_OPT_LOCADDR, &addr) == 0);
	uint8_t *bytes = (void *) &addr.s_in.sa_port;
	uint16_t port = ((uint16_t) bytes[0] << 8) | bytes[1];
	snprintf(url, sizeof(url), "tcp://127.0.0.1:%u", port);
	snprintf(broker_url, sizeof(broker_url), "nmq-tcp://127.0.0.1:%u", port);
	conf *cfg = nng_zalloc(sizeof(*cfg));
	assert(cfg != NULL);
	conf_init(cfg);
	cfg->url = nng_strdup(broker_url);
	if (getenv("ORDER_TEST_PARALLEL")) {
		cfg->parallel = atoi(getenv("ORDER_TEST_PARALLEL"));
	}
	assert(cfg->parallel > 0);
	cfg->websocket.enable = false;
	cfg->qos_duration = 60;
	nng_stream_listener_free(reserved);
	nng_thread *broker;
	assert(nng_thread_create(&broker, (void *) broker_start_with_conf, cfg) == 0);
	assert(test_env_wait_for_tcp_listener(port, 5000));
	unsigned publishers = getenv("ORDER_TEST_PUBLISHERS")
	    ? atoi(getenv("ORDER_TEST_PUBLISHERS")) : 1;
	unsigned count = getenv("ORDER_TEST_MESSAGES")
	    ? atoi(getenv("ORDER_TEST_MESSAGES")) : MESSAGE_COUNT;
	assert(publishers > 0 && publishers <= MAX_PUBLISHERS && count > 0);
	unsigned errors = 0;
	for (uint8_t version = 4; version <= 5; version++) {
		errors += run_order(url, version, 0, 64, publishers, count);
		errors += run_order(url, version, 1, 1, publishers, count);
		errors += run_order(url, version, 1, 64, publishers, count);
	}
	broker_stop_for_test();
	nng_thread_destroy(broker);
#ifndef NANO_PLATFORM_WINDOWS
	unlink(pid_path);
#endif
	return errors ? 1 : 0;
}
