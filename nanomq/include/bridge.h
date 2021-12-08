#ifndef NANOMQ_BRIDGE_H
#define NANOMQ_BRIDGE_H

#include <conf.h>
#include <nng/nng.h>
#include <stdio.h>
#include <stdlib.h>

extern bool topic_filter(const char *origin, const char *input);
extern int  inner_client(nng_socket *sock, const char *url);
int bridge_client(nng_socket *sock, uint16_t nwork, nng_socket inner_sock,
    conf_bridge *config);

extern int client_publish(nng_socket sock, const char *topic, uint8_t *payload,
    uint32_t len, bool dup, uint8_t qos, bool retain);

#endif // NANOMQ_BRIDGE_H