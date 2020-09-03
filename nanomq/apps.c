//
// Copyright 2020 NanoMQ Team, Inc. <jaylin@emqx.io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

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
