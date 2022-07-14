//
// Copyright 2022 NanoMQ Team, Inc. <jaylin@emqx.io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "include/apps.h"
#include "include/broker.h"

#include <stdlib.h>

NANOMQ_APP(broker, broker_dflt, broker_start, broker_stop, broker_restart);

const struct nanomq_app *edge_apps[] = {
	&nanomq_app_broker,
	NULL,
};
