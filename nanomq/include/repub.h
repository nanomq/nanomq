#ifndef NANOMQ_REPUB_H
#define NANOMQ_REPUB_H

#include "nng/mqtt/mqtt_client.h"
#include "nng/supplemental/nanolib/conf.h"
#include "nng/nng.h"
#include <stdio.h>
#include <stdlib.h>

#if defined(SUPP_RULE_ENGINE)
extern int nano_client(nng_socket *sock, repub_t *repub);
extern int nano_client_publish(nng_socket *sock, const char *topic,
    uint8_t *payload, uint32_t len, uint8_t qos, property *props);
#endif

#endif // NANOMQ_REPUB_H