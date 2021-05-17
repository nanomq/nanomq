//
// Copyright 2020 NanoMQ Team, Inc. <jaylin@emqx.io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "include/apps.h"
#include "include/broker.h"
#include "mq.h"

#include <stdlib.h>

#if defined(MQ)
NANOMQ_APP(mq, mqcreate_debug, mqsend_debug, mqreceive_debug, NULL);
#endif
NANOMQ_APP(broker, broker_dflt, broker_start, broker_stop, broker_restart);

#if defined(NANO_DEBUG)

#endif

const struct nanomq_app *edge_apps[] = {
#if defined(MQ)
	&nanomq_app_mq,
#endif
	&nanomq_app_broker,
#if defined(NANO_DEBUG)
//&
#endif
	NULL,
};
