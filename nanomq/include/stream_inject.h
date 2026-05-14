// Internal async publish injection for stream plugins.
// SPDX-License-Identifier: MIT

#ifndef NANOMQ_STREAM_INJECT_H
#define NANOMQ_STREAM_INJECT_H

#include "nng/supplemental/nanolib/conf.h"
#include "nng/nng.h"

#ifdef __cplusplus
extern "C" {
#endif

int  stream_inject_start(conf *cfg, nng_socket broker_sock);
void stream_inject_stop(void);

typedef struct stream_inject_stats {
	uint64_t enqueued;
	uint64_t dropped;
	uint64_t processed;
	uint64_t failed;
	uint64_t send_failed;
	uint64_t queue_len;
} stream_inject_stats;

void stream_inject_get_stats(stream_inject_stats *out);

#ifdef __cplusplus
}
#endif

#endif

