#ifndef WEBHOOK_INPROC_H
#define WEBHOOK_INPROC_H

#include "nng/supplemental/nanolib/conf.h"
#include "nng/nng.h"

#define WEB_HOOK_INPROC_URL "ipc:///tmp/webhook.ipc"

extern int start_webhook_service(conf *conf);
extern int stop_webhook_service(void);

#endif
