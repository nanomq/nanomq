// Stream Plugin skeleton (AI-friendly)
// SPDX-License-Identifier: MIT

#include "nano_sdk.h"     // Broker-facing API used in runtime integration.
#include "nano_skill.h"   // Standalone helpers: window/batch/time/dbc.

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

static nano_skill_window *g_win;
static nano_skill_batch  *g_batch;

static void
on_batch_flush(void *const *items, const uint32_t *sizes, uint32_t count, void *ctx)
{
	(void) ctx;
	// Example sink: append each item as one JSONL line.
	for (uint32_t i = 0; i < count; i++) {
		(void) nano_file_append("/tmp/stream_plugin.jsonl", items[i], sizes[i]);
		(void) nano_file_append("/tmp/stream_plugin.jsonl", "\n", 1);
	}
	nano_log_info("flush count=%u", count);
}

static int
on_msg(const nano_msg *m)
{
	if (m == NULL) {
		return 0;
	}

	if (g_win != NULL && m->payload != NULL && m->payload_len >= 1) {
		double v = (double) ((const uint8_t *) m->payload)[0];
		nano_skill_window_push(g_win, m->ts_ms, v);
		if (nano_skill_window_ready(g_win)) {
			char buf[200];
			int  n = snprintf(buf, sizeof(buf),
			    "{\"ts\":%" PRIu64 ",\"count\":%u,\"avg\":%.2f}",
			    m->ts_ms,
			    nano_skill_window_count(g_win),
			    nano_skill_window_avg(g_win));
			nano_skill_window_reset(g_win);
			if (n > 0) {
				// Publish to broker first; fallback to file when unavailable.
				int rv = nano_mqtt_publish("metrics/example", buf, (uint32_t) n, 0, false);
				if (rv == -ENOSYS) {
					(void) nano_file_append("/tmp/stream_plugin_metrics.jsonl", buf, (uint32_t) n);
					(void) nano_file_append("/tmp/stream_plugin_metrics.jsonl", "\n", 1);
				}
			}
		}
	}

	if (g_batch != NULL) {
		char rec[512];
		int  n = snprintf(rec, sizeof(rec),
		    "{\"ts\":%" PRIu64 ",\"topic\":\"%s\",\"len\":%u}",
		    m->ts_ms, m->topic ? m->topic : "", (unsigned) m->payload_len);
		if (n > 0 && (size_t)n < sizeof(rec)) {
			(void) nano_skill_batch_push(g_batch, rec, (uint32_t) n);
		} else {
			nano_log_warn("Plugin buffer truncated, dropped message on topic %s", m->topic);
		}
	}

	return 0;
}

static void
on_start(void)
{
	nano_log_info("plugin start");
	g_win   = nano_skill_window_tumbling_ms(5000);
	g_batch = nano_skill_batch_open(200, 0, 3000, on_batch_flush, NULL);
}

static void
on_stop(void)
{
	nano_log_info("plugin stop");
	if (g_batch != NULL) {
		nano_skill_batch_close(g_batch);
		g_batch = NULL;
	}
	if (g_win != NULL) {
		nano_skill_window_free(g_win);
		g_win = NULL;
	}
}

int
nano_plugin_init(void)
{
	int rv = nano_register_msg(on_msg);
	if (rv != 0) return rv;
	(void) nano_register_start(on_start);
	(void) nano_register_stop(on_stop);
	return 0;
}

