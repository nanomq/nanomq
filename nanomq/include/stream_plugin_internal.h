// Stream plugin runtime (config-driven) - internal header.
// SPDX-License-Identifier: MIT

#ifndef NANOMQ_STREAM_PLUGIN_INTERNAL_H
#define NANOMQ_STREAM_PLUGIN_INTERNAL_H

#include "nng/supplemental/nanolib/conf.h"
#include "broker.h"

#ifdef __cplusplus
extern "C" {
#endif

int  stream_plugin_load_all(conf *cfg);
int  stream_plugin_start_all(conf *cfg);
void stream_plugin_stop_all(conf *cfg);
void stream_plugin_unload_all(conf *cfg);

// Dispatch from broker SEND path (before hook_entry).
void stream_plugin_pub_dispatch_from_work(nano_work *work);

#ifdef __cplusplus
}
#endif

#endif

