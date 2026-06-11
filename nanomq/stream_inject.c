// Async internal publish injection (function-call based).
//
// Plugins call nano_mqtt_publish_async() to enqueue a publish request.
// A dedicated injector thread dequeues and runs broker publish pipeline
// (handle_pub -> fanout/retain/hook/stream_plugin, etc).
//
// SPDX-License-Identifier: MIT

#include "include/stream_inject.h"
#include "include/nano_sdk.h"
#include "include/broker.h"
#include "include/pub_handler.h"

#include "nng/mqtt/mqtt_client.h"
#include "nng/protocol/mqtt/mqtt.h"
#include "nng/protocol/mqtt/mqtt_parser.h"
#include "nng/supplemental/nanolib/log.h"
#include "nng/supplemental/util/platform.h"

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct inject_item {
	char     *topic;
	uint8_t  *payload;
	uint32_t  payload_len;
	uint8_t   qos;
	bool      retain;
	uint64_t  ts_ms;
	char     *client_id;
} inject_item;

static conf      *g_cfg      = NULL;
static nng_socket  g_broker_sock = { 0 };
static nng_thread **g_workers  = NULL;
static uint32_t     g_worker_num = 0;
static nng_mtx   *g_mtx      = NULL;
static nng_cv    *g_cv       = NULL;
static bool       g_stopping = false;
static stream_plugin_full_op g_full_op = STREAM_PLUGIN_FULL_DROP;

// queue
static inject_item **g_ring = NULL;
static uint32_t      g_cap  = 0;
static uint32_t      g_len  = 0;
static uint32_t      g_head = 0;
static uint32_t      g_tail = 0;

// basic runtime stats
static nng_atomic_u64 *g_stat_enqueued = NULL;
static nng_atomic_u64 *g_stat_dropped = NULL;
static nng_atomic_u64 *g_stat_processed = NULL;
static nng_atomic_u64 *g_stat_failed = NULL;
static nng_atomic_u64 *g_stat_send_failed = NULL;

static void
inject_item_free(inject_item *it)
{
	if (!it) return;
	free(it->topic);
	free(it->payload);
	free(it->client_id);
	free(it);
}

static inject_item *
inject_item_dup(const char *topic, const void *payload, uint32_t len,
    uint8_t qos, bool retain, const char *client_id, uint64_t ts_ms)
{
	inject_item *it = (inject_item *) calloc(1, sizeof(*it));
	if (!it) return NULL;

	it->topic = strdup(topic ? topic : "");
	if (!it->topic) goto oom;

	if (len > 0) {
		it->payload = (uint8_t *) malloc(len);
		if (!it->payload) goto oom;
		memcpy(it->payload, payload, len);
	}
	it->payload_len = len;
	it->qos         = qos;
	it->retain      = retain;
	it->ts_ms       = ts_ms ? ts_ms : (uint64_t) nng_clock();
	it->client_id   = client_id ? strdup(client_id) : NULL;
	if (client_id && !it->client_id) goto oom;
	return it;

oom:
	inject_item_free(it);
	return NULL;
}

static conn_param *
make_cparam(const char *clientid, uint8_t proto_ver)
{
	conn_param *cparam = NULL;
	conn_param_alloc(&cparam);
	conn_param_set_clientid(cparam, clientid);
	conn_param_set_proto_ver(cparam, proto_ver);
	return cparam;
}

static inline void
stat_inc(nng_atomic_u64 *a)
{
	if (a) {
		nng_atomic_inc64(a);
	}
}

static void
inject_worker(void *arg)
{
	(void) arg;
	nng_ctx worker_ctx = { 0 };
	nng_aio *worker_aio = NULL;
	if (nng_ctx_open(&worker_ctx, g_broker_sock) != 0 ||
	    nng_aio_alloc(&worker_aio, NULL, NULL) != 0) {
		log_error("stream_inject: worker init failed");
		if (worker_aio) {
			nng_aio_free(worker_aio);
		}
		if (worker_ctx.id != 0) {
			nng_ctx_close(worker_ctx);
		}
		return;
	}

	for (;;) {
		nng_mtx_lock(g_mtx);
		while (g_len == 0 && !g_stopping) {
			nng_cv_wait(g_cv);
		}
		if (g_stopping && g_len == 0) {
			nng_mtx_unlock(g_mtx);
			break;
		}
		inject_item *it = g_ring[g_head];
		g_ring[g_head] = NULL;
		g_head = (g_head + 1) % g_cap;
		g_len--;
		nng_cv_wake1(g_cv);
		nng_mtx_unlock(g_mtx);

		if (!it || !g_cfg) {
			inject_item_free(it);
			continue;
		}

		// Build MQTT PUBLISH nng_msg in NanoMQ internal format:
		// - msg header: fixed header byte + remaining length varint
		// - msg body: variable header (topic + packet id) + payload
		nng_msg *msg = NULL;
		if (nng_msg_alloc(&msg, 0) != 0) {
			inject_item_free(it);
			continue;
		}
		nng_msg_set_timestamp(msg, (nng_time) it->ts_ms);

		const uint16_t tlen = (uint16_t) strlen(it->topic ? it->topic : "");
		const uint32_t body_len = 2u + (uint32_t) tlen + (it->qos ? 2u : 0u) + it->payload_len;

		// fixed header first byte
		uint8_t hdr0 = 0x30; // PUBLISH
		if (it->retain) hdr0 |= 0x01;
		hdr0 |= (uint8_t) ((it->qos & 0x03) << 1);
		(void) nng_msg_header_append(msg, &hdr0, 1);

		// remaining length varint
		uint32_t x = body_len;
		do {
			uint8_t byte = x % 128;
			x /= 128;
			if (x > 0) byte |= 0x80;
			(void) nng_msg_header_append(msg, &byte, 1);
		} while (x > 0);

		// body: topic length + topic
		uint8_t tlen_be[2] = { (uint8_t)(tlen >> 8), (uint8_t)(tlen & 0xff) };
		(void) nng_msg_append(msg, tlen_be, 2);
		if (tlen > 0) {
			(void) nng_msg_append(msg, it->topic, tlen);
		}
		// packet id for QoS>0 (use 1)
		if (it->qos) {
			uint8_t pid_be[2] = { 0x00, 0x01 };
			(void) nng_msg_append(msg, pid_be, 2);
		}
		// payload
		if (it->payload_len > 0) {
			(void) nng_msg_append(msg, it->payload, it->payload_len);
		}

		// Run broker publish pipeline to compute msg_infos, then send.
		nano_work w;
		memset(&w, 0, sizeof(w));
		w.proto      = PROTO_STREAM_INJECT;
		w.proto_ver  = MQTT_PROTOCOL_VERSION_v311;
		w.msg        = msg;
		w.config     = g_cfg;
		w.db         = get_broker_db();
		w.db_ret     = get_broker_retain_db();
		w.pid.id     = 0;
		w.cparam     = make_cparam(it->client_id ? it->client_id : "stream_plugin", w.proto_ver);
		w.pipe_ct    = nng_zalloc(sizeof(struct pipe_content));
		init_pipe_content(w.pipe_ct);

		// Mark as CMD_PUBLISH for consistency (handle_pub doesn't rely on it).
		nng_msg_set_cmd_type(w.msg, CMD_PUBLISH);
		w.pub_packet = (struct pub_packet_struct *) nng_zalloc(
		    sizeof(struct pub_packet_struct));
		if (w.pub_packet == NULL) {
			log_error("stream_inject: alloc pub_packet failed");
			nng_free(w.pipe_ct, sizeof(struct pipe_content));
			nng_msg_free(w.msg);
			inject_item_free(it);
			continue;
		}
		if (decode_pub_message(&w, w.proto_ver) != 0) {
			log_error("stream_inject: decode_pub_message failed");
			free_pub_packet(w.pub_packet);
			nng_free(w.pipe_ct, sizeof(struct pipe_content));
			nng_msg_free(w.msg);
			inject_item_free(it);
			continue;
		}
		w.code = handle_pub(&w, w.pipe_ct, w.proto_ver, false);

		if (w.code == SUCCESS && w.pipe_ct && w.pipe_ct->msg_infos) {
			nng_msg *smsg = w.msg; // reuse the same msg
			cvector(mqtt_msg_info) msg_infos = w.pipe_ct->msg_infos;
			if (cvector_size(msg_infos) && encode_pub_message(smsg, &w, PUBLISH)) {
				for (int i = 0; i < cvector_size(msg_infos); i++) {
					mqtt_msg_info *mi = &msg_infos[i];
					if (mi->pipe == 0) continue;
					nng_msg_clone(smsg);
					w.pid.id = mi->pipe;
					nng_aio_set_prov_data(worker_aio, &w.pid.id);
					nng_aio_set_msg(worker_aio, smsg);
					nng_ctx_send(worker_ctx, worker_aio);
					nng_aio_wait(worker_aio);
					int rv = nng_aio_result(worker_aio);
					if (rv != 0) {
						log_debug("stream_inject: send to pipe %u failed: %d", w.pid.id, rv);
						nng_msg *fm = nng_aio_get_msg(worker_aio);
						if (fm) nng_msg_free(fm);
						stat_inc(g_stat_send_failed);
					}
				}
			}
			w.msg = smsg;
		}
		if (w.code == SUCCESS) {
			stat_inc(g_stat_processed);
		} else {
			stat_inc(g_stat_failed);
		}
		log_debug("stream_inject: processed topic=%s rc=%d", it->topic, (int) w.code);

		// cleanup like broker END state
		if (w.pub_packet) {
			free_pub_packet(w.pub_packet);
			w.pub_packet = NULL;
		}
		if (w.pipe_ct) {
			if (w.pipe_ct->msg_infos) {
				cvector_free(w.pipe_ct->msg_infos);
				w.pipe_ct->msg_infos = NULL;
			}
			nng_free(w.pipe_ct, sizeof(struct pipe_content));
			w.pipe_ct = NULL;
		}
		if (w.cparam) {
			conn_param_free(w.cparam);
			w.cparam = NULL;
		}
		if (w.msg) {
			nng_msg_free(w.msg);
			w.msg = NULL;
		}
		inject_item_free(it);
	}

	if (worker_aio) {
		nng_aio_free(worker_aio);
	}
	if (worker_ctx.id != 0) {
		nng_ctx_close(worker_ctx);
	}
}

int
stream_inject_start(conf *cfg, nng_socket broker_sock)
{
	if (g_workers != NULL) return 0;
	if (cfg == NULL) return 0;
	if (!cfg->stream_inject.enable) {
		log_info("stream_inject: disabled by config");
		return 0;
	}

	g_cfg = cfg;
	g_broker_sock = broker_sock;
	g_cap = cfg->stream_inject.queue_cap ? cfg->stream_inject.queue_cap : 4096;
	g_worker_num = 1;
	if (cfg->stream_inject.worker_num > 1) {
		log_warn("stream_inject: force worker_num=1 to keep send path simple");
	}
	g_full_op = cfg->stream_inject.full_op;
	g_ring = (inject_item **) calloc(g_cap, sizeof(inject_item *));
	if (!g_ring) return -1;

	if (nng_mtx_alloc(&g_mtx) != 0) return -1;
	if (nng_cv_alloc(&g_cv, g_mtx) != 0) return -1;

	g_stopping = false;
	g_len = 0; g_head = 0; g_tail = 0;
	nng_atomic_alloc64(&g_stat_enqueued);
	nng_atomic_alloc64(&g_stat_dropped);
	nng_atomic_alloc64(&g_stat_processed);
	nng_atomic_alloc64(&g_stat_failed);
	nng_atomic_alloc64(&g_stat_send_failed);

	g_workers = (nng_thread **) calloc(g_worker_num, sizeof(nng_thread *));
	if (!g_workers) {
		log_error("stream_inject: alloc workers failed");
		return -1;
	}
	for (uint32_t i = 0; i < g_worker_num; i++) {
		int rv = nng_thread_create(&g_workers[i], inject_worker, NULL);
		if (rv != 0) {
			log_error("stream_inject: nng_thread_create[%u] failed: %d", i, rv);
			return -1;
		}
	}
	log_info("stream_inject: started (cap=%u, workers=%u, full_op=%s)",
	    g_cap, g_worker_num, g_full_op == STREAM_PLUGIN_FULL_BLOCK ? "block" : "drop");
	return 0;
}

void
stream_inject_stop(void)
{
	if (g_workers == NULL) return;
	nng_mtx_lock(g_mtx);
	g_stopping = true;
	nng_cv_wake(g_cv);
	nng_mtx_unlock(g_mtx);
	for (uint32_t i = 0; i < g_worker_num; i++) {
		if (g_workers[i]) {
			nng_thread_destroy(g_workers[i]);
		}
	}
	free(g_workers);
	g_workers = NULL;

	if (g_ring) {
		for (uint32_t i = 0; i < g_cap; i++) {
			inject_item_free(g_ring[i]);
		}
		free(g_ring);
		g_ring = NULL;
	}
	if (g_cv) {
		nng_cv_free(g_cv);
		g_cv = NULL;
	}
	if (g_mtx) {
		nng_mtx_free(g_mtx);
		g_mtx = NULL;
	}
	g_cfg = NULL;
	log_info("stream_inject: stopped (enq=%" PRIu64 ", drop=%" PRIu64
	         ", processed=%" PRIu64 ", failed=%" PRIu64 ", send_failed=%" PRIu64 ")",
	    g_stat_enqueued ? nng_atomic_get64(g_stat_enqueued) : 0,
	    g_stat_dropped ? nng_atomic_get64(g_stat_dropped) : 0,
	    g_stat_processed ? nng_atomic_get64(g_stat_processed) : 0,
	    g_stat_failed ? nng_atomic_get64(g_stat_failed) : 0,
	    g_stat_send_failed ? nng_atomic_get64(g_stat_send_failed) : 0);
	if (g_stat_enqueued) nng_atomic_free64(g_stat_enqueued);
	if (g_stat_dropped) nng_atomic_free64(g_stat_dropped);
	if (g_stat_processed) nng_atomic_free64(g_stat_processed);
	if (g_stat_failed) nng_atomic_free64(g_stat_failed);
	if (g_stat_send_failed) nng_atomic_free64(g_stat_send_failed);
	g_stat_enqueued = g_stat_dropped = g_stat_processed = g_stat_failed = g_stat_send_failed = NULL;
	g_cap = g_len = g_head = g_tail = 0;
	g_worker_num = 0;
}

int
nano_mqtt_publish_async(const char *topic, const void *payload, uint32_t len,
    uint8_t qos, bool retain)
{
	if (topic == NULL || topic[0] == '\0') return -EINVAL;
	if (payload == NULL && len > 0) return -EINVAL;
	if (qos > 2) return -EINVAL;
	if (g_workers == NULL || g_mtx == NULL) return -ENOSYS;

	inject_item *it = inject_item_dup(topic, payload, len, qos, retain, "stream_plugin", 0);
	if (!it) return -ENOMEM;

	nng_mtx_lock(g_mtx);
	while (!g_stopping && g_len >= g_cap && g_full_op == STREAM_PLUGIN_FULL_BLOCK) {
		nng_cv_wait(g_cv);
	}
	if (g_len >= g_cap || g_stopping) {
		nng_mtx_unlock(g_mtx);
		inject_item_free(it);
		stat_inc(g_stat_dropped);
		log_warn("stream_inject: queue full, drop topic=%s", topic);
		return -EAGAIN;
	}
	g_ring[g_tail] = it;
	g_tail = (g_tail + 1) % g_cap;
	g_len++;
	stat_inc(g_stat_enqueued);
	nng_cv_wake1(g_cv);
	nng_mtx_unlock(g_mtx);
	log_debug("stream_inject: enqueued topic=%s len=%u", topic, len);
	return 0;
}

// Keep old API as sync wrapper: enqueue and return.
int
nano_mqtt_publish(const char *topic, const void *payload, uint32_t len, uint8_t qos, bool retain)
{
	return nano_mqtt_publish_async(topic, payload, len, qos, retain);
}

void
stream_inject_get_stats(stream_inject_stats *out)
{
	if (out == NULL) {
		return;
	}
	memset(out, 0, sizeof(*out));
	out->enqueued    = g_stat_enqueued ? nng_atomic_get64(g_stat_enqueued) : 0;
	out->dropped     = g_stat_dropped ? nng_atomic_get64(g_stat_dropped) : 0;
	out->processed   = g_stat_processed ? nng_atomic_get64(g_stat_processed) : 0;
	out->failed      = g_stat_failed ? nng_atomic_get64(g_stat_failed) : 0;
	out->send_failed = g_stat_send_failed ? nng_atomic_get64(g_stat_send_failed) : 0;
	if (g_mtx) {
		nng_mtx_lock(g_mtx);
		out->queue_len = g_len;
		nng_mtx_unlock(g_mtx);
	}
}

