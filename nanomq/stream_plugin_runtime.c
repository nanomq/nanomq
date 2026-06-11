// Stream plugin runtime (D/A2 without shell): config-driven stream_plugin.spX.
//
// - Loads configured .so plugins via dlopen
// - Provides nano_register_msg/start/stop + nano_log + nano_file_append
// - Routes broker PUBLISH to a dedicated stream-plugin dispatch thread
//
// Plugin authors should compile algorithmic helpers (window/batch/dbc) into
// their .so via nanomq/skill/.
//
// SPDX-License-Identifier: MIT

#include "include/stream_plugin_internal.h"
#include "include/nano_sdk.h"
#include "include/pub_handler.h"

#include "nng/supplemental/nanolib/conf.h"
#include "nng/mqtt/mqtt_client.h"
#include "nng/protocol/pipeline0/pull.h"
#include "nng/protocol/pipeline0/push.h"
#include "nng/protocol/mqtt/mqtt_parser.h" // topic_filter
#include "nng/supplemental/nanolib/log.h"
#include "nng/supplemental/util/platform.h"

#include <dlfcn.h>
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(SUPP_PLUGIN)

#define SP_FAIL_OPEN_CONSEC_THRESHOLD 20

typedef struct sp_qmsg {
	nano_msg  m;
	char     *topic;
	uint8_t  *payload;
	char     *client_id;
} sp_qmsg;

typedef struct sp_inst {
	conf_stream_plugin_node *cfg;
	void                    *handle;
	nano_on_msg_fn           on_msg;
	nano_lifecycle_fn        on_start;
	nano_lifecycle_fn        on_stop;

	// async runtime
	bool      async_started;
	bool      stopping;
	nng_thread *thr;
	nng_mtx   *q_mtx;
	nng_cv    *q_cv;
	sp_qmsg  **q_ring;
	uint32_t   q_cap;
	uint32_t   q_len;
	uint32_t   q_head;
	uint32_t   q_tail;

	// fail-open counters
	nng_atomic_u64 *total_calls;
	nng_atomic_u64 *total_errors;
	nng_atomic_u64 *dropped_full;
	uint32_t   consec_errors;
	bool       disabled;
} sp_inst;

static __thread sp_inst *tls_loading_inst = NULL;
static nng_thread       *sp_route_thr      = NULL;
static nng_socket        sp_route_push     = NNG_SOCKET_INITIALIZER;
static nng_socket        sp_route_pull     = NNG_SOCKET_INITIALIZER;
static nng_atomic_bool  *sp_route_stopping = NULL;
static nng_atomic_u64   *sp_route_dropped  = NULL;
static nng_mtx          *sp_route_send_mtx = NULL;
static nng_cv           *sp_route_send_cv  = NULL;
static nng_aio          *sp_route_send_aio = NULL;
static nng_lmq          *sp_route_send_lmq = NULL;
static bool              sp_route_send_busy = false;
static const size_t      SP_ROUTE_LMQ_INIT_CAP = 1024;
static const size_t      SP_ROUTE_LMQ_MAX_CAP  = 10000;
static const char       *SP_ROUTE_IPC_URL  = "inproc://nanomq_stream_plugin_route";

static void sp_qmsg_free(sp_qmsg *q);

static inline void
sp_atomic_inc(nng_atomic_u64 *a)
{
	if (a) {
		nng_atomic_inc64(a);
	}
}

static inline uint64_t
sp_atomic_get(nng_atomic_u64 *a)
{
	return a ? nng_atomic_get64(a) : 0;
}

static inline void
sp_socket_reset(nng_socket *s)
{
	if (s) {
		memset(s, 0, sizeof(*s));
	}
}

static bool
sp_route_read_field(const uint8_t *body, size_t len, size_t *off, void *out, size_t n)
{
	if (body == NULL || off == NULL || out == NULL) return false;
	if (*off + n > len) return false;
	memcpy(out, body + *off, n);
	*off += n;
	return true;
}

static void
sp_route_send_aio_cb(void *arg)
{
	(void) arg;
	if (sp_route_send_aio == NULL) return;

	int rv = nng_aio_result(sp_route_send_aio);
	if (rv != 0) {
		sp_atomic_inc(sp_route_dropped);
		nng_msg *m = nng_aio_get_msg(sp_route_send_aio);
		if (m) {
			nng_msg_free(m);
		}
	}

	if (sp_route_send_mtx && sp_route_send_cv) {
		nng_msg *next = NULL;
		nng_mtx_lock(sp_route_send_mtx);
		if (sp_route_send_lmq && !nng_lmq_empty(sp_route_send_lmq)) {
			if (nng_lmq_get(sp_route_send_lmq, &next) == 0 && next != NULL) {
				sp_route_send_busy = true;
			} else {
				sp_route_send_busy = false;
			}
		} else {
			sp_route_send_busy = false;
		}
		nng_cv_wake1(sp_route_send_cv);
		nng_mtx_unlock(sp_route_send_mtx);

		if (next != NULL) {
			nng_aio_set_msg(sp_route_send_aio, next);
			nng_send_aio(sp_route_push, sp_route_send_aio);
		}
	}
}

static void
sp_qmsg_free(sp_qmsg *q)
{
	if (!q) return;
	// One-allocation layout: struct + topic + payload + client_id.
	free(q);
}

static void sp_dispatch_to_cfg(conf *cfg, const nano_msg *m);
static void sp_route_send_ensure_stopped(void);

static void
sp_route_worker(void *arg)
{
	(void) arg;
	for (;;) {
		nng_msg *msg = NULL;
		int rv = nng_recvmsg(sp_route_pull, &msg, 0);
		if (rv != 0) {
			if (sp_route_stopping && nng_atomic_get_bool(sp_route_stopping)) {
				break;
			}
			log_warn("stream_plugin: route recv failed: %d %s", rv, nng_strerror(rv));
			continue;
		}
		if (msg == NULL) {
			continue;
		}

		const uint8_t *body = nng_msg_body(msg);
		size_t         len  = nng_msg_len(msg);
		size_t         off  = 0;

		uintptr_t cfg_ptr = 0;
		uint64_t  ts      = 0;
		uint32_t  plen    = 0;
		uint8_t   qos     = 0;
		uint8_t   retain  = 0;
		uint16_t  tlen    = 0;
		uint16_t  cid_len = 0;

		if (!sp_route_read_field(body, len, &off, &cfg_ptr, sizeof(cfg_ptr)) ||
		    !sp_route_read_field(body, len, &off, &ts, sizeof(ts)) ||
		    !sp_route_read_field(body, len, &off, &plen, sizeof(plen)) ||
		    !sp_route_read_field(body, len, &off, &qos, sizeof(qos)) ||
		    !sp_route_read_field(body, len, &off, &retain, sizeof(retain)) ||
		    !sp_route_read_field(body, len, &off, &tlen, sizeof(tlen)) ||
		    !sp_route_read_field(body, len, &off, &cid_len, sizeof(cid_len))) {
			nng_msg_free(msg);
			continue;
		}

		if (off + (size_t) tlen + (size_t) plen + (size_t) cid_len > len) {
			nng_msg_free(msg);
			continue;
		}

		const uint8_t *topic_src = body + off;
		off += tlen;
		const void *payload = (const void *) (body + off);
		off += plen;

		char *topic = (char *) malloc((size_t) tlen + 1);
		if (topic == NULL) {
			nng_msg_free(msg);
			continue;
		}
		if (tlen > 0) {
			memcpy(topic, topic_src, tlen);
		}
		topic[tlen] = '\0';

		char *cid = NULL;
		if (cid_len > 0) {
			cid = (char *) malloc((size_t) cid_len + 1);
			if (cid == NULL) {
				free(topic);
				nng_msg_free(msg);
				continue;
			}
			memcpy(cid, body + off, cid_len);
			cid[cid_len] = '\0';
		}

		nano_msg m = {
			.ts_ms = ts,
			.topic = topic,
			.payload = payload,
			.payload_len = plen,
			.qos = qos,
			.retain = (retain != 0),
			.client_id = cid,
		};

		sp_dispatch_to_cfg((conf *) cfg_ptr, &m);
		free(topic);
		free(cid);
		nng_msg_free(msg);
	}
}

static int
sp_route_start(void)
{
	if (sp_route_thr != NULL) return 0;
	int rv;
	if (sp_route_stopping == NULL) {
		nng_atomic_alloc_bool(&sp_route_stopping);
	}
	if (sp_route_stopping) {
		nng_atomic_set_bool(sp_route_stopping, false);
	}
	if (sp_route_dropped == NULL) {
		nng_atomic_alloc64(&sp_route_dropped);
	}
	if (sp_route_dropped) {
		nng_atomic_set64(sp_route_dropped, 0);
	}
	if (sp_route_send_mtx == NULL) {
		if (nng_mtx_alloc(&sp_route_send_mtx) != 0) {
			log_error("stream_plugin: route send mtx alloc failed");
			return -1;
		}
	}
	if (sp_route_send_cv == NULL) {
		if (nng_cv_alloc(&sp_route_send_cv, sp_route_send_mtx) != 0) {
			log_error("stream_plugin: route send cv alloc failed");
			return -1;
		}
	}
	if (sp_route_send_aio == NULL) {
		if (nng_aio_alloc(&sp_route_send_aio, sp_route_send_aio_cb, NULL) != 0) {
			log_error("stream_plugin: route send aio alloc failed");
			return -1;
		}
	}
	if (sp_route_send_lmq == NULL) {
		if (nng_lmq_alloc(&sp_route_send_lmq, SP_ROUTE_LMQ_INIT_CAP) != 0) {
			log_error("stream_plugin: route send lmq alloc failed");
			return -1;
		}
	}
	if (sp_route_send_mtx) {
		nng_mtx_lock(sp_route_send_mtx);
		sp_route_send_busy = false;
		nng_mtx_unlock(sp_route_send_mtx);
	}
	if ((rv = nng_push0_open(&sp_route_push)) != 0) {
		log_error("stream_plugin: route push open failed: %d %s", rv, nng_strerror(rv));
		return -1;
	}
	if ((rv = nng_pull0_open(&sp_route_pull)) != 0) {
		log_error("stream_plugin: route pull open failed: %d %s", rv, nng_strerror(rv));
		nng_close(sp_route_push);
		sp_socket_reset(&sp_route_push);
		return -1;
	}
	if ((rv = nng_listen(sp_route_pull, SP_ROUTE_IPC_URL, NULL, 0)) != 0) {
		log_error("stream_plugin: route listen failed: %d %s", rv, nng_strerror(rv));
		nng_close(sp_route_pull);
		nng_close(sp_route_push);
		sp_socket_reset(&sp_route_pull);
		sp_socket_reset(&sp_route_push);
		return -1;
	}
	if ((rv = nng_dial(sp_route_push, SP_ROUTE_IPC_URL, NULL, 0)) != 0) {
		log_error("stream_plugin: route dial failed: %d %s", rv, nng_strerror(rv));
		nng_close(sp_route_pull);
		nng_close(sp_route_push);
		sp_socket_reset(&sp_route_pull);
		sp_socket_reset(&sp_route_push);
		return -1;
	}
	if ((rv = nng_thread_create(&sp_route_thr, sp_route_worker, NULL)) != 0) {
		log_error("stream_plugin: route thread create failed: %d %s", rv, nng_strerror(rv));
		nng_close(sp_route_pull);
		nng_close(sp_route_push);
		sp_socket_reset(&sp_route_pull);
		sp_socket_reset(&sp_route_push);
		return -1;
	}
	return 0;
}

static void
sp_route_stop(void)
{
	if (sp_route_thr == NULL) return;
	if (sp_route_stopping) {
		nng_atomic_set_bool(sp_route_stopping, true);
	}
	nng_close(sp_route_push);
	nng_close(sp_route_pull);
	sp_socket_reset(&sp_route_push);
	sp_socket_reset(&sp_route_pull);

	nng_thread_destroy(sp_route_thr);
	sp_route_thr = NULL;

	sp_route_send_ensure_stopped();
}

static void
sp_route_enqueue(conf *cfg, uint64_t ts, const char *topic, const void *payload,
    uint32_t plen, uint8_t qos, bool retain, const char *client_id)
{
	if (cfg == NULL || topic == NULL) return;
	if (sp_route_thr == NULL) return;

	uint16_t tlen = (uint16_t) strlen(topic);
	uint16_t clen = (uint16_t) ((client_id == NULL) ? 0 : strlen(client_id));
	size_t header_sz = sizeof(uintptr_t) + sizeof(uint64_t) + sizeof(uint32_t) +
	                   sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint16_t) +
	                   sizeof(uint16_t);
	size_t msg_sz = header_sz + (size_t) tlen + (size_t) plen + (size_t) clen;

	nng_msg *msg = NULL;
	if (nng_msg_alloc(&msg, 0) != 0) {
		sp_atomic_inc(sp_route_dropped);
		return;
	}

	uintptr_t cfg_ptr = (uintptr_t) cfg;
	uint8_t retain_u8 = retain ? 1 : 0;
	if (nng_msg_append(msg, &cfg_ptr, sizeof(cfg_ptr)) != 0 ||
	    nng_msg_append(msg, &ts, sizeof(ts)) != 0 ||
	    nng_msg_append(msg, &plen, sizeof(plen)) != 0 ||
	    nng_msg_append(msg, &qos, sizeof(qos)) != 0 ||
	    nng_msg_append(msg, &retain_u8, sizeof(retain_u8)) != 0 ||
	    nng_msg_append(msg, &tlen, sizeof(tlen)) != 0 ||
	    nng_msg_append(msg, &clen, sizeof(clen)) != 0 ||
	    nng_msg_append(msg, topic, tlen) != 0) {
		sp_atomic_inc(sp_route_dropped);
		nng_msg_free(msg);
		return;
	}
	if (plen > 0) {
		if (nng_msg_append(msg, payload, plen) != 0) {
			sp_atomic_inc(sp_route_dropped);
			nng_msg_free(msg);
			return;
		}
	}
	if (clen > 0) {
		if (nng_msg_append(msg, client_id, clen) != 0) {
			sp_atomic_inc(sp_route_dropped);
			nng_msg_free(msg);
			return;
		}
	}
	if (nng_msg_len(msg) != msg_sz) {
		sp_atomic_inc(sp_route_dropped);
		nng_msg_free(msg);
		return;
	}

	if (sp_route_send_mtx == NULL || sp_route_send_aio == NULL) {
		sp_atomic_inc(sp_route_dropped);
		nng_msg_free(msg);
		return;
	}

	nng_mtx_lock(sp_route_send_mtx);
	if (sp_route_send_busy || (sp_route_stopping && nng_atomic_get_bool(sp_route_stopping))) {
		if (sp_route_send_lmq && nng_lmq_full(sp_route_send_lmq)) {
			size_t cap = nng_lmq_cap(sp_route_send_lmq);
			if (cap >= SP_ROUTE_LMQ_MAX_CAP) {
				nng_mtx_unlock(sp_route_send_mtx);
				sp_atomic_inc(sp_route_dropped);
				nng_msg_free(msg);
				return;
			}
			size_t new_cap = cap + (cap / 2);
			if (new_cap < cap + 1) new_cap = cap + 1;
			if (new_cap > SP_ROUTE_LMQ_MAX_CAP) new_cap = SP_ROUTE_LMQ_MAX_CAP;
			if (nng_lmq_resize(sp_route_send_lmq, new_cap) != 0) {
				nng_mtx_unlock(sp_route_send_mtx);
				sp_atomic_inc(sp_route_dropped);
				nng_msg_free(msg);
				return;
			}
		}
		if (sp_route_send_lmq && nng_lmq_put(sp_route_send_lmq, msg) == 0) {
			nng_mtx_unlock(sp_route_send_mtx);
			return;
		}
		nng_mtx_unlock(sp_route_send_mtx);
		sp_atomic_inc(sp_route_dropped);
		nng_msg_free(msg);
		return;
	}
	sp_route_send_busy = true;
	nng_aio_set_msg(sp_route_send_aio, msg);
	nng_send_aio(sp_route_push, sp_route_send_aio);
	nng_mtx_unlock(sp_route_send_mtx);
}

static void
sp_route_send_resources_free(void)
{
	if (sp_route_send_cv) {
		nng_cv_free(sp_route_send_cv);
		sp_route_send_cv = NULL;
	}
	if (sp_route_send_mtx) {
		nng_mtx_free(sp_route_send_mtx);
		sp_route_send_mtx = NULL;
	}
	if (sp_route_send_aio) {
		nng_aio_free(sp_route_send_aio);
		sp_route_send_aio = NULL;
	}
	if (sp_route_send_lmq) {
		nng_msg *m = NULL;
		while (nng_lmq_get(sp_route_send_lmq, &m) == 0) {
			if (m) nng_msg_free(m);
			m = NULL;
		}
		nng_lmq_free(sp_route_send_lmq);
		sp_route_send_lmq = NULL;
	}
	sp_route_send_busy = false;
}

static void
sp_route_send_ensure_stopped(void)
{
	if (sp_route_send_mtx && sp_route_send_cv) {
		nng_mtx_lock(sp_route_send_mtx);
		while (sp_route_send_busy || (sp_route_send_lmq && !nng_lmq_empty(sp_route_send_lmq))) {
			nng_cv_wait(sp_route_send_cv);
		}
		nng_mtx_unlock(sp_route_send_mtx);
	}
}

static sp_qmsg *
sp_qmsg_dup(uint64_t ts, const char *topic, const void *payload, uint32_t plen,
    uint8_t qos, bool retain, const char *client_id)
{
	const char *src_topic = topic ? topic : "";
	size_t tlen = strlen(src_topic);
	size_t cid_len = client_id ? strlen(client_id) : 0;
	size_t total = sizeof(sp_qmsg) + tlen + 1 + (size_t) plen + cid_len + 1;

	sp_qmsg *q = (sp_qmsg *) calloc(1, total);
	if (!q) return NULL;

	uint8_t *cursor = (uint8_t *) (q + 1);
	q->topic = (char *) cursor;
	memcpy(q->topic, src_topic, tlen);
	q->topic[tlen] = '\0';
	cursor += tlen + 1;

	if (plen > 0) {
		q->payload = cursor;
		memcpy(q->payload, payload, plen);
		cursor += plen;
	}

	if (client_id) {
		q->client_id = (char *) cursor;
		memcpy(q->client_id, client_id, cid_len);
		q->client_id[cid_len] = '\0';
	}

	q->m.ts_ms       = ts;
	q->m.topic       = q->topic;
	q->m.payload     = q->payload;
	q->m.payload_len = plen;
	q->m.qos         = qos;
	q->m.retain      = retain;
	q->m.client_id   = q->client_id;
	return q;
}

static void
sp_worker(void *arg)
{
	sp_inst *inst = (sp_inst *) arg;
	if (!inst) return;

	for (;;) {
		nng_mtx_lock(inst->q_mtx);
		while (inst->q_len == 0 && !inst->stopping) {
			nng_cv_wait(inst->q_cv);
		}

		if (inst->stopping && inst->q_len == 0) {
			nng_mtx_unlock(inst->q_mtx);
			break;
		}

		sp_qmsg *q = inst->q_ring[inst->q_head];
		inst->q_ring[inst->q_head] = NULL;
		inst->q_head = (inst->q_head + 1) % inst->q_cap;
		inst->q_len--;
		// wake a producer possibly blocked on full queue
		nng_cv_wake1(inst->q_cv);
		nng_mtx_unlock(inst->q_mtx);

		if (q && inst->on_msg) {
			int rc = inst->on_msg(&q->m);
			sp_atomic_inc(inst->total_calls);
			if (rc == 0) {
				inst->consec_errors = 0;
			} else {
				sp_atomic_inc(inst->total_errors);
				inst->consec_errors++;
				if (inst->consec_errors >= SP_FAIL_OPEN_CONSEC_THRESHOLD) {
					inst->disabled = true;
					log_warn("stream_plugin[%s]: auto-disabled after %u consecutive errors",
					    inst->cfg && inst->cfg->name ? inst->cfg->name : "unknown",
					    inst->consec_errors);
				}
			}
		}
		sp_qmsg_free(q);
	}
}

static int
sp_async_start(sp_inst *inst)
{
	if (!inst || inst->async_started) return 0;
	if (!inst->cfg) return 0;
	if (inst->cfg->mode != STREAM_PLUGIN_MODE_ASYNC) return 0;

	uint32_t cap = inst->cfg->queue_cap ? inst->cfg->queue_cap : 4096;
	inst->q_cap  = cap;
	inst->q_ring = (sp_qmsg **) calloc(cap, sizeof(sp_qmsg *));
	if (!inst->q_ring) return -1;

	if (nng_mtx_alloc(&inst->q_mtx) != 0) return -1;
	if (nng_cv_alloc(&inst->q_cv, inst->q_mtx) != 0) return -1;

	inst->stopping      = false;
	inst->q_len         = 0;
	inst->q_head        = 0;
	inst->q_tail        = 0;
	inst->async_started = true;

	int rv = nng_thread_create(&inst->thr, sp_worker, inst);
	if (rv != 0) {
		inst->async_started = false;
		return -1;
	}
	return 0;
}

static void
sp_async_stop(sp_inst *inst)
{
	if (!inst || !inst->async_started) return;

	nng_mtx_lock(inst->q_mtx);
	inst->stopping = true;
	nng_cv_wake(inst->q_cv);
	nng_mtx_unlock(inst->q_mtx);

	if (inst->thr) {
		nng_thread_destroy(inst->thr);
		inst->thr = NULL;
	}

	// free remaining queued messages if any (worker should have drained)
	if (inst->q_ring) {
		for (uint32_t i = 0; i < inst->q_cap; i++) {
			sp_qmsg_free(inst->q_ring[i]);
		}
		free(inst->q_ring);
		inst->q_ring = NULL;
	}

	if (inst->q_cv) {
		nng_cv_free(inst->q_cv);
		inst->q_cv = NULL;
	}
	if (inst->q_mtx) {
		nng_mtx_free(inst->q_mtx);
		inst->q_mtx = NULL;
	}
	inst->async_started = false;
}

static void
sp_dispatch(sp_inst *inst, const nano_msg *m)
{
	if (!inst || !inst->on_msg || !m) return;
	if (inst->disabled) return;
	if (!inst->cfg || inst->cfg->mode != STREAM_PLUGIN_MODE_ASYNC) {
		int rc = inst->on_msg(m);
		sp_atomic_inc(inst->total_calls);
		if (rc == 0) {
			inst->consec_errors = 0;
		} else {
			sp_atomic_inc(inst->total_errors);
			inst->consec_errors++;
			if (inst->consec_errors >= SP_FAIL_OPEN_CONSEC_THRESHOLD) {
				inst->disabled = true;
				log_warn("stream_plugin[%s]: auto-disabled after %u consecutive errors",
				    inst->cfg && inst->cfg->name ? inst->cfg->name : "unknown",
				    inst->consec_errors);
			}
		}
		return;
	}

	// async mode: enqueue deep-copied message
	if (!inst->async_started) {
		// should not happen after start_all; fall back to sync
		(void) inst->on_msg(m);
		return;
	}

	sp_qmsg *q = sp_qmsg_dup(m->ts_ms, m->topic, m->payload, m->payload_len,
	    m->qos, m->retain, m->client_id);
	if (!q) return;

	nng_mtx_lock(inst->q_mtx);

	if (inst->q_len >= inst->q_cap) {
        inst->dropped_full++;
        if (inst->dropped_full % 1000 == 1) {
            log_warn("stream_plugin[%s]: queue full, force dropping message to protect broker", inst->cfg->name);
        }
        nng_mtx_unlock(inst->q_mtx);
        sp_qmsg_free(q);
        return;
	}

	if (inst->stopping) {
		nng_mtx_unlock(inst->q_mtx);
		sp_qmsg_free(q);
		return;
	}

	if (inst->q_len >= inst->q_cap) {
		// drop
		nng_mtx_unlock(inst->q_mtx);
		sp_atomic_inc(inst->dropped_full);
		sp_qmsg_free(q);
		return;
	}

	inst->q_ring[inst->q_tail] = q;
	inst->q_tail = (inst->q_tail + 1) % inst->q_cap;
	inst->q_len++;
	nng_cv_wake1(inst->q_cv);
	nng_mtx_unlock(inst->q_mtx);
}

static void
sp_dispatch_to_cfg(conf *cfg, const nano_msg *m)
{
	if (cfg == NULL || m == NULL || m->topic == NULL) return;
	if (cfg->stream_plugin.count == 0) return;

	for (size_t i = 0; i < cfg->stream_plugin.count; i++) {
		conf_stream_plugin_node *n = cfg->stream_plugin.nodes[i];
		sp_inst *inst = n->runtime;
		if (!inst) continue;
		if (!topic_filter(n->topic, (char *) m->topic)) continue;
		sp_dispatch(inst, m);
	}
}

static void
sdk_vlog(int level, const char *fmt, va_list ap)
{
	char buf[1024];
	(void) vsnprintf(buf, sizeof(buf), fmt, ap);
	log_log(level, "stream_plugin", 0, "user", "%s", buf);
}

void nano_log_info(const char *fmt, ...)  { va_list ap; va_start(ap, fmt); sdk_vlog(NNG_LOG_INFO, fmt, ap); va_end(ap); }
void nano_log_warn(const char *fmt, ...)  { va_list ap; va_start(ap, fmt); sdk_vlog(NNG_LOG_WARN, fmt, ap); va_end(ap); }
void nano_log_error(const char *fmt, ...) { va_list ap; va_start(ap, fmt); sdk_vlog(NNG_LOG_ERROR, fmt, ap); va_end(ap); }

uint64_t nano_time_ms(void) { return (uint64_t) nng_clock(); }

int
nano_file_append(const char *path, const void *data, uint32_t len)
{
	if (path == NULL || (data == NULL && len > 0) || len == 0) return -EINVAL;
	FILE *fp = fopen(path, "ab");
	if (fp == NULL) return -errno;
	size_t n = fwrite(data, 1, len, fp);
	fclose(fp);
	return (n == len) ? 0 : -EIO;
}

// nano_mqtt_publish / nano_mqtt_publish_async are implemented in stream_inject.c

int nano_register_msg(nano_on_msg_fn fn)
{
	if (tls_loading_inst == NULL || fn == NULL) return -EINVAL;
	tls_loading_inst->on_msg = fn;
	return 0;
}
int nano_register_start(nano_lifecycle_fn fn)
{
	if (tls_loading_inst == NULL || fn == NULL) return -EINVAL;
	tls_loading_inst->on_start = fn;
	return 0;
}
int nano_register_stop(nano_lifecycle_fn fn)
{
	if (tls_loading_inst == NULL || fn == NULL) return -EINVAL;
	tls_loading_inst->on_stop = fn;
	return 0;
}

// dbc stubs
nano_dbc *nano_dbc_load(const char *path) { (void)path; return NULL; }
int nano_dbc_decode(nano_dbc *dbc, uint32_t can_id, const uint8_t *data, uint8_t dlc,
    nano_dbc_signal *out, uint32_t cap, uint32_t *outn)
{
	(void)dbc; (void)can_id; (void)data; (void)dlc; (void)out; (void)cap;
	if (outn) *outn = 0;
	return -ENOSYS;
}
void nano_dbc_free(nano_dbc *dbc) { (void)dbc; }

static int
load_one(conf_stream_plugin_node *node)
{
	sp_inst *inst = nng_zalloc(sizeof(*inst));
	if (inst == NULL) return -1;
	inst->cfg = node;
	nng_atomic_alloc64(&inst->total_calls);
	nng_atomic_alloc64(&inst->total_errors);
	nng_atomic_alloc64(&inst->dropped_full);
	if (inst->total_calls) nng_atomic_set64(inst->total_calls, 0);
	if (inst->total_errors) nng_atomic_set64(inst->total_errors, 0);
	if (inst->dropped_full) nng_atomic_set64(inst->dropped_full, 0);

	void *h = dlopen(node->path, RTLD_NOW | RTLD_LOCAL);
	if (h == NULL) {
		log_error("stream_plugin: dlopen(%s) failed: %s", node->path, dlerror());
		if (inst->total_calls) nng_atomic_free64(inst->total_calls);
		if (inst->total_errors) nng_atomic_free64(inst->total_errors);
		if (inst->dropped_full) nng_atomic_free64(inst->dropped_full);
		nng_free(inst, sizeof(*inst));
		return -1;
	}
	inst->handle = h;

	int (*init_fn)(void) = dlsym(h, "nano_plugin_init");
	if (init_fn == NULL) {
		log_error("stream_plugin: %s missing nano_plugin_init", node->path);
		dlclose(h);
		if (inst->total_calls) nng_atomic_free64(inst->total_calls);
		if (inst->total_errors) nng_atomic_free64(inst->total_errors);
		if (inst->dropped_full) nng_atomic_free64(inst->dropped_full);
		nng_free(inst, sizeof(*inst));
		return -1;
	}

	tls_loading_inst = inst;
	int rv = init_fn();
	tls_loading_inst = NULL;

	if (rv != 0 || inst->on_msg == NULL) {
		log_error("stream_plugin: %s init failed rv=%d on_msg=%p",
		    node->path, rv, (void *)inst->on_msg);
		dlclose(h);
		if (inst->total_calls) nng_atomic_free64(inst->total_calls);
		if (inst->total_errors) nng_atomic_free64(inst->total_errors);
		if (inst->dropped_full) nng_atomic_free64(inst->dropped_full);
		nng_free(inst, sizeof(*inst));
		return -1;
	}

	node->runtime = inst;
	node->handle  = h;
	log_info("stream_plugin: loaded %s topic=%s", node->path, node->topic);
	return 0;
}

int
stream_plugin_load_all(conf *cfg)
{
#if !defined(SUPP_PLUGIN)
	(void)cfg;
	return 0;
#else
	if (cfg == NULL) return 0;
	for (size_t i = 0; i < cfg->stream_plugin.count; i++) {
		(void) load_one(cfg->stream_plugin.nodes[i]);
	}
	return 0;
#endif
}

int
stream_plugin_start_all(conf *cfg)
{
#if !defined(SUPP_PLUGIN)
	(void)cfg;
	return 0;
#else
	if (cfg == NULL) return 0;
	if (sp_route_start() != 0) {
		log_error("stream_plugin: route worker start failed");
	}
	for (size_t i = 0; i < cfg->stream_plugin.count; i++) {
		conf_stream_plugin_node *n = cfg->stream_plugin.nodes[i];
		sp_inst *inst = n->runtime;
		if (!inst) continue;
		(void) sp_async_start(inst);
		if (inst->on_start) inst->on_start();
	}
	return 0;
#endif
}

void
stream_plugin_stop_all(conf *cfg)
{
#if defined(SUPP_PLUGIN)
	if (cfg == NULL) return;
	sp_route_stop();
	for (size_t i = 0; i < cfg->stream_plugin.count; i++) {
		conf_stream_plugin_node *n = cfg->stream_plugin.nodes[i];
		sp_inst *inst = n->runtime;
		if (!inst) continue;
		// stop async worker after draining queued messages
		sp_async_stop(inst);
		if (inst->on_stop) inst->on_stop();
		log_info("stream_plugin[%s]: calls=%" PRIu64 " errors=%" PRIu64
		         " dropped_full=%" PRIu64 " route_drop=%" PRIu64
		         " disabled=%s",
		    n->name ? n->name : "unknown",
		    sp_atomic_get(inst->total_calls), sp_atomic_get(inst->total_errors),
		    sp_atomic_get(inst->dropped_full), sp_atomic_get(sp_route_dropped),
		    inst->disabled ? "true" : "false");
	}
#else
	(void)cfg;
#endif
}

void
stream_plugin_unload_all(conf *cfg)
{
#if defined(SUPP_PLUGIN)
	if (cfg == NULL) return;
	sp_route_stop();
	for (size_t i = 0; i < cfg->stream_plugin.count; i++) {
		conf_stream_plugin_node *n = cfg->stream_plugin.nodes[i];
		sp_inst *inst = n->runtime;
		if (!inst) continue;
		sp_async_stop(inst);
		dlclose(inst->handle);
		if (inst->total_calls) nng_atomic_free64(inst->total_calls);
		if (inst->total_errors) nng_atomic_free64(inst->total_errors);
		if (inst->dropped_full) nng_atomic_free64(inst->dropped_full);
		nng_free(inst, sizeof(*inst));
		n->runtime = NULL;
		n->handle = NULL;
	}
	if (sp_route_dropped) {
		nng_atomic_free64(sp_route_dropped);
		sp_route_dropped = NULL;
	}
	sp_route_send_ensure_stopped();
	sp_route_send_resources_free();
	if (sp_route_stopping) {
		nng_atomic_free_bool(sp_route_stopping);
		sp_route_stopping = NULL;
	}
#else
	(void)cfg;
#endif
}

void
stream_plugin_pub_dispatch_from_work(nano_work *work)
{
	if (work == NULL || work->config == NULL || work->pub_packet == NULL) return;
	conf *cfg = work->config;
	if (cfg->stream_plugin.count == 0) return;

	const char *topic = work->pub_packet->var_header.publish.topic_name.body;
	if (topic == NULL) return;

	const char *cid = (const char *) conn_param_get_clientid(work->cparam);
	uint64_t ts = (uint64_t) nng_msg_get_timestamp(work->msg);
	if (ts == 0) ts = nano_time_ms();

	const void *payload = work->pub_packet->payload.data;
	uint32_t plen = work->pub_packet->payload.len;
	uint8_t qos = work->pub_packet->fixed_header.qos;
	bool retain = work->pub_packet->fixed_header.retain;

	// Queue to dedicated route thread, avoid executing plugin callbacks
	// on broker state machine thread.
	sp_route_enqueue(cfg, ts, topic, payload, plen, qos, retain, cid);
}

#else // !SUPP_PLUGIN

int  stream_plugin_load_all(conf *cfg)  { (void)cfg; return 0; }
int  stream_plugin_start_all(conf *cfg) { (void)cfg; return 0; }
void stream_plugin_stop_all(conf *cfg)  { (void)cfg; }
void stream_plugin_unload_all(conf *cfg){ (void)cfg; }
void stream_plugin_pub_dispatch_from_work(nano_work *work) { (void)work; }

#endif

