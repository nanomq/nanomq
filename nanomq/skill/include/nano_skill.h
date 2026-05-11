// NanoMQ Skill Library (standalone helpers for plugins)
//
// Goals:
// - A generic helper library that can be compiled/linked directly into `.so`
//   plugins (window, batching, DBC, etc.).
// - No dependency on broker-exported NanoMQ symbols; compile these `.c` files
//   directly into your plugin.
//
// Scope:
// - Broker-injection APIs like nano_mqtt_publish are not implemented here.
// - This library focuses on pure algorithms and optional generic I/O helpers.
//
// SPDX-License-Identifier: MIT

#ifndef NANOMQ_NANO_SKILL_H
#define NANOMQ_NANO_SKILL_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// =========================================================
// time
// =========================================================

// monotonic time in ms
uint64_t nano_skill_time_ms(void);

// =========================================================
// window: numeric tumbling window
// =========================================================

typedef struct nano_skill_window nano_skill_window;

nano_skill_window *nano_skill_window_tumbling_ms(uint32_t window_ms);
void               nano_skill_window_push(nano_skill_window *w, uint64_t ts_ms, double v);
bool               nano_skill_window_ready(nano_skill_window *w);
double             nano_skill_window_avg(nano_skill_window *w);
double             nano_skill_window_max(nano_skill_window *w);
double             nano_skill_window_min(nano_skill_window *w);
uint32_t           nano_skill_window_count(nano_skill_window *w);
void               nano_skill_window_reset(nano_skill_window *w);
void               nano_skill_window_free(nano_skill_window *w);

// =========================================================
// batch: count/bytes/time triggers with background worker
// =========================================================

typedef struct nano_skill_batch nano_skill_batch;

typedef void (*nano_skill_batch_flush_fn)(void *const *items,
                                          const uint32_t *sizes,
                                          uint32_t count,
                                          void *ctx);

// At least one trigger must be non-zero; on_flush cannot be NULL.
nano_skill_batch *nano_skill_batch_open(uint32_t max_count,
                                        uint32_t max_total_bytes,
                                        uint32_t flush_ms,
                                        nano_skill_batch_flush_fn on_flush,
                                        void *ctx);

// push deep-copies data (caller may free data after return).
// Return: 0 on success, <0 on failure (-EINVAL/-ENOMEM/-ESHUTDOWN)
int  nano_skill_batch_push(nano_skill_batch *b, const void *data, uint32_t len);
int  nano_skill_batch_flush(nano_skill_batch *b);
void nano_skill_batch_close(nano_skill_batch *b);

// =========================================================
// dbc: reserved standard API (backend TBD)
// =========================================================

typedef struct nano_skill_dbc nano_skill_dbc;

typedef struct nano_skill_dbc_signal {
	const char *name;
	double      value;
	const char *unit;
} nano_skill_dbc_signal;

// Current default implementation: stub (returns NULL / -ENOSYS)
nano_skill_dbc *nano_skill_dbc_load(const char *path);
int             nano_skill_dbc_decode(nano_skill_dbc *dbc, uint32_t can_id,
                                      const uint8_t *data, uint8_t dlc,
                                      nano_skill_dbc_signal *out, uint32_t cap,
                                      uint32_t *outn);
void            nano_skill_dbc_free(nano_skill_dbc *dbc);

#ifdef __cplusplus
}
#endif

#endif // NANOMQ_NANO_SKILL_H

