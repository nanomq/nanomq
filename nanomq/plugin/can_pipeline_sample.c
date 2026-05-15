// Sample stream plugin: CAN-like pipeline (AI-friendly).
//
// This plugin is designed as a reference for “describe requirement -> generate .so”.
//
// - Input: topic filter is configured in NanoMQ (not hard-coded here).
// - Demo parsing: BatteryTemp is faked as payload[0] (0-255).
// - Outputs:
//   1) Alert: batt_temp > 55 -> publish (if nano_mqtt_publish available) OR append to file.
//   2) Metrics: 5s tumbling window -> publish (or append to file).
//   3) Batch: every 50 msgs or 3s -> flush a JSON array to /tmp/canp_batch.log
//
// Build:
//   gcc -O2 -Wall -Wextra -fPIC -shared \
//     -I<NanoMQ>/nanomq/include -I<NanoMQ>/nanomq/skill/include \
//     can_pipeline_sample.c <NanoMQ>/nanomq/skill/src/nano_skill_time.c \
//     <NanoMQ>/nanomq/skill/src/nano_skill_window.c \
//     <NanoMQ>/nanomq/skill/src/nano_skill_batch.c \
//     <NanoMQ>/nanomq/skill/src/nano_skill_dbc_stub.c -lpthread \
//     -o can_pipeline_sample.so
//
// SPDX-License-Identifier: MIT

#include "nano_sdk.h"
#include "nano_skill.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define BATCH_LOG       "/tmp/canp_batch.log"
#define ALERT_TOPIC     "alert/can/batt_overheat"
#define METRICS_TOPIC   "metrics/can/batt_temp"
#define ALERT_THRESHOLD 55.0
#define WINDOW_MS       5000
#define BATCH_MAX_COUNT 50
#define BATCH_FLUSH_MS  3000

static nano_skill_window *g_win;
static nano_skill_batch  *g_batch;

static void
append_line(const char *path, const char *s, uint32_t n)
{
	(void) nano_file_append(path, s, n);
	(void) nano_file_append(path, "\n", 1);
}

static void
on_batch_flush(void *const *items, const uint32_t *sizes,
    uint32_t count, void *ctx)
{
	(void) ctx;
	uint32_t total = 4;
	for (uint32_t i = 0; i < count; i++) {
		total += sizes[i] + 1;
	}
	char *buf = (char *) malloc(total);
	if (buf == NULL) {
		return;
	}
	uint32_t pos = 0;
	buf[pos++]   = '[';
	for (uint32_t i = 0; i < count; i++) {
		if (i > 0) {
			buf[pos++] = ',';
		}
		memcpy(buf + pos, items[i], sizes[i]);
		pos += sizes[i];
	}
	buf[pos++] = ']';
	buf[pos++] = '\n';
	(void) nano_file_append(BATCH_LOG, buf, pos);
	free(buf);
}

static int
on_msg(const nano_msg *m)
{
	if (m == NULL || m->payload == NULL || m->payload_len < 1) {
		return 0;
	}
	double batt_temp = (double) ((const uint8_t *) m->payload)[0];

	// (1) Alert
	if (batt_temp > ALERT_THRESHOLD) {
		char line[200];
		int  n = snprintf(line, sizeof(line),
		    "{\"ts\":%" PRIu64 ",\"alert\":\"batt_overheat\","
		    "\"value\":%.1f,\"client\":\"%s\"}",
		    m->ts_ms, batt_temp, m->client_id ? m->client_id : "");
		if (n > 0) {
			int rv = nano_mqtt_publish(ALERT_TOPIC, line, (uint32_t) n, 0, false);
			if (rv == -ENOSYS) {
				append_line("/tmp/canp_alert.jsonl", line, (uint32_t) n);
			}
		}
	}

	// (2) Window metrics
	if (g_win != NULL) {
		nano_skill_window_push(g_win, m->ts_ms, batt_temp);
		if (nano_skill_window_ready(g_win)) {
			char line[260];
			int  n = snprintf(line, sizeof(line),
			    "{\"ts\":%" PRIu64 ",\"window_ms\":%d,"
			    "\"count\":%u,\"avg\":%.2f,\"max\":%.2f,"
			    "\"min\":%.2f}",
			    m->ts_ms, WINDOW_MS,
			    nano_skill_window_count(g_win),
			    nano_skill_window_avg(g_win),
			    nano_skill_window_max(g_win),
			    nano_skill_window_min(g_win));
			nano_skill_window_reset(g_win);
			if (n > 0) {
				int rv = nano_mqtt_publish(METRICS_TOPIC, line, (uint32_t) n, 0, false);
				if (rv == -ENOSYS) {
					append_line("/tmp/canp_metrics.jsonl", line, (uint32_t) n);
				}
			}
		}
	}

	// (3) Batch sink
	if (g_batch != NULL) {
		char rec[200];
		int  n = snprintf(rec, sizeof(rec),
		    "{\"ts\":%" PRIu64 ",\"topic\":\"%s\",\"client\":\"%s\","
		    "\"v\":%.1f}",
		    m->ts_ms, m->topic ? m->topic : "",
		    m->client_id ? m->client_id : "", batt_temp);
		if (n > 0) {
			(void) nano_skill_batch_push(g_batch, rec, (uint32_t) n);
		}
	}
	return 0;
}

static void
on_start(void)
{
	g_win   = nano_skill_window_tumbling_ms(WINDOW_MS);
	g_batch = nano_skill_batch_open(BATCH_MAX_COUNT, 0, BATCH_FLUSH_MS, on_batch_flush, NULL);
}

static void
on_stop(void)
{
	if (g_batch) {
		nano_skill_batch_close(g_batch);
		g_batch = NULL;
	}
	if (g_win) {
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

