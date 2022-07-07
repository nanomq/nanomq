#ifndef NANOMQ_BRIDGE_H
#define NANOMQ_BRIDGE_H

#include "nng/supplemental/nanolib/conf.h"
#include "nng/nng.h"
#include <stdio.h>
#include <stdlib.h>

typedef struct {
	nng_socket *      sock;
	conf_bridge_node *config;
} bridge_param;

extern bool topic_filter(const char *origin, const char *input);
extern int  bridge_client(
     nng_socket *sock, conf *config, conf_bridge_node *bridge_conf);
extern nng_msg *bridge_publish_msg(const char *topic, uint8_t *payload,
    uint32_t len, bool dup, uint8_t qos, bool retain);

#endif // NANOMQ_BRIDGE_H