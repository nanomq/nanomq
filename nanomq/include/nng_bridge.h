//
// Copyright 2024 NanoMQ Team, Inc. <jaylin@emqx.io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//
#ifndef NNG_BRIDGE_H
#define NNG_BRIDGE_H

#include <stdio.h>
#include <stdlib.h>
#include "nng/mqtt/mqtt_client.h"
#include "nng/nng.h"
#include "nng/supplemental/nanolib/conf.h"
#include "nng/supplemental/util/platform.h"
#include "broker.h"
#include "pub_handler.h"

extern void nng_pub_handler(nano_work *, nng_msg *);
extern int  nng_proxy_pub_init(conf_nng_pub_node *);
extern int  nng_proxy_sub_init(conf_nng_sub_node *, nano_work *);

#endif
