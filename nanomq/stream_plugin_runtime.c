// Stream plugin runtime (D/A2 without shell): config-driven stream_plugin.spX.
//
// - Loads configured .so plugins via dlopen
// - Provides nano_register_msg/start/stop + nano_log + nano_file_append
// - Dispatches broker PUBLISH (topic-filtered) before webhook hook_entry
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
	uint64_t   total_calls;
	uint64_t   total_errors;
	uint64_t   dropped_full;
	uint32_t   consec_errors;
	bool       disabled;
} sp_inst;

static __thread sp_inst *tls_loading_inst = NULL;

static void
sp_qmsg_free(sp_qmsg *q)
{
	if (!q) return;
	free(q->topic);
	free(q->payload);
	free(q->client_id);
	free(q);
}

static sp_qmsg *
sp_qmsg_dup(uint64_t ts, const char *topic, const void *payload, uint32_t plen,
    uint8_t qos, bool retain, const char *client_id)
{
	sp_qmsg *q = (sp_qmsg *) calloc(1, sizeof(*q));
	if (!q) return NULL;

	q->topic = topic ? strdup(topic) : strdup("");
	if (!q->topic) goto oom;

	if (plen > 0) {
		q->payload = (uint8_t *) malloc(plen);
		if (!q->payload) goto oom;
		memcpy(q->payload, payload, plen);
	}

	q->client_id = client_id ? strdup(client_id) : NULL;
	if (client_id && !q->client_id) goto oom;

	q->m.ts_ms       = ts;
	q->m.topic       = q->topic;
	q->m.payload     = q->payload;
	q->m.payload_len = plen;
	q->m.qos         = qos;
	q->m.retain      = retain;
	q->m.client_id   = q->client_id;
	return q;

oom:
	sp_qmsg_free(q);
	return NULL;
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
			inst->total_calls++;
			if (rc == 0) {
				inst->consec_errors = 0;
			} else {
				inst->total_errors++;
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
		inst->total_calls++;
		if (rc == 0) {
			inst->consec_errors = 0;
		} else {
			inst->total_errors++;
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
	while (inst->q_len >= inst->q_cap && !inst->stopping &&
	    inst->cfg->full_op == STREAM_PLUGIN_FULL_BLOCK) {
		nng_cv_wait(inst->q_cv);
	}

	if (inst->stopping) {
		nng_mtx_unlock(inst->q_mtx);
		sp_qmsg_free(q);
		return;
	}

	if (inst->q_len >= inst->q_cap) {
		// drop
		nng_mtx_unlock(inst->q_mtx);
		inst->dropped_full++;
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

	void *h = dlopen(node->path, RTLD_NOW | RTLD_LOCAL);
	if (h == NULL) {
		log_error("stream_plugin: dlopen(%s) failed: %s", node->path, dlerror());
		nng_free(inst, sizeof(*inst));
		return -1;
	}
	inst->handle = h;

	int (*init_fn)(void) = dlsym(h, "nano_plugin_init");
	if (init_fn == NULL) {
		log_error("stream_plugin: %s missing nano_plugin_init", node->path);
		dlclose(h);
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
	for (size_t i = 0; i < cfg->stream_plugin.count; i++) {
		conf_stream_plugin_node *n = cfg->stream_plugin.nodes[i];
		sp_inst *inst = n->runtime;
		if (!inst) continue;
		// stop async worker after draining queued messages
		sp_async_stop(inst);
		if (inst->on_stop) inst->on_stop();
		log_info("stream_plugin[%s]: calls=%" PRIu64 " errors=%" PRIu64
		         " dropped_full=%" PRIu64 " disabled=%s",
		    n->name ? n->name : "unknown",
		    inst->total_calls, inst->total_errors, inst->dropped_full,
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
	for (size_t i = 0; i < cfg->stream_plugin.count; i++) {
		conf_stream_plugin_node *n = cfg->stream_plugin.nodes[i];
		sp_inst *inst = n->runtime;
		if (!inst) continue;
		sp_async_stop(inst);
		dlclose(inst->handle);
		nng_free(inst, sizeof(*inst));
		n->runtime = NULL;
		n->handle = NULL;
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

	nano_msg m = {
		.ts_ms = ts,
		.topic = topic,
		.payload = payload,
		.payload_len = plen,
		.qos = qos,
		.retain = retain,
		.client_id = cid,
	};

	for (size_t i = 0; i < cfg->stream_plugin.count; i++) {
		conf_stream_plugin_node *n = cfg->stream_plugin.nodes[i];
		sp_inst *inst = n->runtime;
		if (!inst) continue;
		if (!topic_filter(n->topic, (char *) topic)) continue;
		sp_dispatch(inst, &m);
	}
}

#else // !SUPP_PLUGIN

int  stream_plugin_load_all(conf *cfg)  { (void)cfg; return 0; }
int  stream_plugin_start_all(conf *cfg) { (void)cfg; return 0; }
void stream_plugin_stop_all(conf *cfg)  { (void)cfg; }
void stream_plugin_unload_all(conf *cfg){ (void)cfg; }
void stream_plugin_pub_dispatch_from_work(nano_work *work) { (void)work; }

#endif

