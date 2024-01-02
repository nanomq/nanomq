#ifndef WEBHOOK_INPROC_H
#define WEBHOOK_INPROC_H

#include "nng/supplemental/nanolib/conf.h"
#include "nng/nng.h"

#define HOOK_IPC_URL "ipc:///tmp/nanomq_hook.ipc"

extern int start_webhook_service(conf *conf);
extern int stop_webhook_service(void);

#endif
