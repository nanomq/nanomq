
#include "include/apps.h"
#include "broker.h"
#include "mq.h"

#include <stdlib.h>

NANOMQ_APP(mq, mqcreate_debug, mqsend_debug, mqreceive_debug);
NANOMQ_APP(broker, broker_dflt, broker_start, NULL);

#if defined(NANO_DEBUG)

#endif

const struct nanomq_app *edge_apps[] = {
	&nanomq_app_mq,
	&nanomq_app_broker,
#if defined(NANO_DEBUG)
	//&
#endif
	NULL,
};
