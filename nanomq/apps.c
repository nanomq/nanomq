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
#include "include/client.h"
#include "include/mq.h"
#include "include/nngcat.h"
#include "include/bench.h"
#include "include/nng_proxy.h"
#include "include/zmq_gateway.h"

#include <stdlib.h>

#if defined(MQ)
NANOMQ_APP(mq, mqcreate_debug, mqsend_debug, mqreceive_debug, NULL);
#endif
NANOMQ_APP(broker, broker_dflt, broker_start, broker_stop, broker_restart);
#if defined(SUPP_CLIENT)
NANOMQ_APP(pub, pub_dflt, pub_start, NULL, client_stop);
NANOMQ_APP(sub, sub_dflt, sub_start, NULL, client_stop);
NANOMQ_APP(conn, conn_dflt, conn_start, NULL, client_stop);
#endif

#if defined(SUPP_NNG_PROXY)
NANOMQ_APP(nngproxy, nng_proxy_start, NULL, NULL, NULL);
NANOMQ_APP(nngpub0, nng_pub0_dflt, nng_pub0_start, NULL, nng_client0_stop);
NANOMQ_APP(nngsub0, nng_sub0_dflt, nng_sub0_start, NULL, nng_client0_stop);
#endif

#if defined(SUPP_ZMQ_GATEWAY)
NANOMQ_APP(gateway, gateway_dflt, gateway_start, NULL, NULL);
#endif
#if defined(SUPP_BENCH)
NANOMQ_APP(bench, bench_dflt, bench_start, NULL, NULL);
#endif
NANOMQ_APP(nngcat, nng_cat_dflt, NULL, NULL, NULL);
#if defined(NANO_DEBUG)

#endif

const struct nanomq_app *edge_apps[] = {
#if defined(MQ)
	&nanomq_app_mq,
#endif
	&nanomq_app_broker,
#if defined(SUPP_CLIENT)
	&nanomq_app_pub,
	&nanomq_app_sub,
	&nanomq_app_conn,
#endif
#if defined(SUPP_NNG_PROXY)
	&nanomq_app_nngproxy,
	&nanomq_app_nngcat,
#endif
#if defined(SUPP_ZMQ_GATEWAY)
	&nanomq_app_gateway,
#endif
#if defined(SUPP_BENCH)
	&nanomq_app_bench,
#endif
#if defined(NANO_DEBUG)
//&
#endif
	NULL,
};
