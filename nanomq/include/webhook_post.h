#ifndef WEBHOOK_POST_H
#define WEBHOOK_POST_H

#include "webhook_inproc.h"
#include "broker.h"

extern int hook_entry(nano_work *work, uint8_t reason);
extern int hook_exchange_init(conf *nanomq_conf, uint64_t num_ctx);
extern int hook_exchange_sender_init(conf *nanomq_conf, struct work **works, uint64_t num_ctx);

#ifdef SUPP_PARQUET
extern int hook_last_flush();
#endif

#endif
