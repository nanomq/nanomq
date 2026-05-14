//
// NanoMQ Stream Plugin SDK (AI-friendly)
//
// Goal: provide a single header that humans/AI can use to generate
// compilable `.so` plugin code.
//
// Conventions:
// - Fixed entry point: `int nano_plugin_init(void);`
// - Register callbacks in `nano_plugin_init` (on_msg/on_start/on_stop).
// - Use standard `nano_*` APIs for publish/file/window/batch/log/time.
//
// Note: this header defines the API contract. Actual interface availability
// depends on symbols exported by the broker build. Unimplemented APIs should
// return -ENOSYS or NULL.
//
// SPDX-License-Identifier: MIT
//

#ifndef NANOMQ_NANO_SDK_H
#define NANOMQ_NANO_SDK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ==============================
// Version
// ==============================

#define NANO_SDK_VERSION 1

// ==============================
// Message structure
// ==============================
//
// Pointers in `nano_msg` (topic/payload/client_id) are broker-owned.
// They may become invalid after `on_msg` returns (async mode copies data
// and keeps it valid during callback execution).
//
typedef struct nano_msg {
	uint64_t    ts_ms;        // Broker receive timestamp in milliseconds.
	const char *topic;        // NUL-terminated MQTT topic.
	const void *payload;      // Payload bytes; NULL allowed when payload_len==0.
	uint32_t    payload_len;  // payload bytes
	uint8_t     qos;          // 0/1/2
	bool        retain;       // retain flag
	const char *client_id;    // May be NULL.
} nano_msg;

// ==============================
// Callback signatures
// ==============================

// on_msg: called once per matched message.
// - return 0: success
// - return <0: failure (logged only, broker main flow continues)
typedef int (*nano_on_msg_fn)(const nano_msg *m);

typedef void (*nano_lifecycle_fn)(void);

// ==============================
// Registration (must be called in nano_plugin_init)
// ==============================
//
// Error code conventions (int return value):
// - 0: success
// - -EINVAL: invalid parameter
// - -ENOMEM: out of memory
//
int nano_register_msg(nano_on_msg_fn fn);
int nano_register_start(nano_lifecycle_fn fn);
int nano_register_stop(nano_lifecycle_fn fn);

// ==============================
// Publish (plugin -> broker)
// ==============================
//
// Semantics: reinject message into local broker and run full publish pipeline
// (ACL/retain/sub dispatch).
//
// - topic: wildcards are not allowed
// - payload may be NULL when len==0
//
// Threading: thread-safe (callable from any thread).
//
// Return:
// - 0: success (injected/enqueued)
// - <0: failure (-EINVAL/-ENOMEM/-ENOSYS/-EIO/...)
int nano_mqtt_publish(const char *topic, const void *payload, uint32_t len,
                      uint8_t qos, bool retain);

// Async injection variant: enqueue only, without waiting for broker completion.
// Suitable for source plugins/high-rate replay to avoid blocking caller threads.
int nano_mqtt_publish_async(const char *topic, const void *payload, uint32_t len,
                            uint8_t qos, bool retain);

// ==============================
// File append (plugin -> file)
// ==============================
//
// Semantics: append data to file.
// Threading: thread-safe, but each call may open/write/close;
// prefer batching for high-frequency writes.
int nano_file_append(const char *path, const void *data, uint32_t len);

// ==============================
// Window aggregation (tumbling window)
// ==============================
//
// Purpose: numeric tumbling time-window avg/max/min/count aggregation.
//
// Threading: a single handle is not guaranteed thread-safe;
// one window should be used by one processing thread.
//
typedef struct nano_window nano_window;

nano_window *nano_window_tumbling_ms(uint32_t window_ms);
void         nano_window_push(nano_window *w, uint64_t ts_ms, double v);
bool         nano_window_ready(nano_window *w);
double       nano_window_avg(nano_window *w);
double       nano_window_max(nano_window *w);
double       nano_window_min(nano_window *w);
uint32_t     nano_window_count(nano_window *w);
void         nano_window_reset(nano_window *w);
void         nano_window_free(nano_window *w);

// ==============================
// Batch aggregation (flush triggered by count/bytes/time)
// ==============================
//
// Purpose: aggregate high-frequency data into larger chunks to reduce
// disk/network overhead.
// Threading: push on one batch handle is not guaranteed thread-safe;
// flush callback runs on batch worker thread.
//
typedef struct nano_batch nano_batch;

typedef void (*nano_batch_flush_fn)(void *const *items,
                                    const uint32_t *sizes,
                                    uint32_t count,
                                    void *ctx);

// At least one trigger must be non-zero; on_flush cannot be NULL.
nano_batch *nano_batch_open(uint32_t max_count,
                            uint32_t max_total_bytes,
                            uint32_t flush_ms,
                            nano_batch_flush_fn on_flush,
                            void *ctx);

int  nano_batch_push(nano_batch *b, const void *data, uint32_t len);
int  nano_batch_flush(nano_batch *b);
void nano_batch_close(nano_batch *b);

// ==============================
// Logging + time
// ==============================
//
// Threading: thread-safe.
void     nano_log_info(const char *fmt, ...);
void     nano_log_warn(const char *fmt, ...);
void     nano_log_error(const char *fmt, ...);
uint64_t nano_time_ms(void);

// ==============================
// DBC (reserved standard API for generated code)
// ==============================
//
// Note: DBC backend may be unavailable. In that case, nano_dbc_load
// returns NULL and nano_dbc_decode returns -ENOSYS.
//
typedef struct nano_dbc nano_dbc;

typedef struct nano_dbc_signal {
	const char *name;   // Points to dbc-owned string, valid for dbc lifetime.
	double      value;  // Physical value.
	const char *unit;   // May be NULL.
} nano_dbc_signal;

nano_dbc *nano_dbc_load(const char *path);
int       nano_dbc_decode(nano_dbc *dbc, uint32_t can_id,
                          const uint8_t *data, uint8_t dlc,
                          nano_dbc_signal *out, uint32_t cap,
                          uint32_t *outn);
void      nano_dbc_free(nano_dbc *dbc);

// ==============================
// Plugin entry (implemented by plugin)
// ==============================
//
// Called once after broker dlopen(). Register callbacks via nano_register_* here.
// Return 0 on successful load; non-zero means load failure.
//
int nano_plugin_init(void);

#ifdef __cplusplus
}
#endif

#endif // NANOMQ_NANO_SDK_H

