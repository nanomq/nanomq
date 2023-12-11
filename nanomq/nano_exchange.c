#include "include/nanomq.h"
#include "include/nano_exchange.h"
#include "nng/nng.h"

#include "include/bridge.h"
#include "nng/mqtt/mqtt_client.h"
#include "nng/nng.h"
#include "nng/protocol/mqtt/mqtt.h"
#include "nng/supplemental/nanolib/log.h"
#include "nng/supplemental/util/platform.h"
#include "nng/supplemental/nanolib/utils.h"
#include "nng/protocol/mqtt/mqtt_parser.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "include/nanomq.h"
#include "include/mqtt_api.h"

//#include "nng/exchange/exchange_client.h"

#define NNG_OPT_EXCHANGE_BIND             "exchange-client-bind"

int
nano_exchange_client(nng_socket *sock, conf *config, conf_exchange_client_node *node)
{
	int rv;

	if ((rv = nng_exchange_client_open(sock)) != 0) {
		log_error("nng_exchange_client_open failed %d", rv);
		return rv;
	}
	void *ex;
	ex = node->exchange;
	nng_socket_set_ptr(*sock, NNG_OPT_EXCHANGE_BIND, ex);

	return 0;
}
