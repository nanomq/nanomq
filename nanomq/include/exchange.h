#ifndef NANO_EXCHANGE_H
#define NANO_EXCHANGE_H

#include "nng/nng.h"
#include "nng/supplemental/nanolib/conf.h"

int nano_exchange_client(nng_socket *sock, conf *config, conf_exchange_client_node *node);

#endif
