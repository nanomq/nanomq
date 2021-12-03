#ifndef NANOMQ_BRIDGE_H
#define NANOMQ_BRIDGE_H

#include <nng/nng.h>
#include <stdio.h>
#include <stdlib.h>

extern int inner_client(nng_socket *sock, const char *url);
extern int bridge_client(
    nng_socket *sock, const char *url, uint16_t nwork, nng_socket inner_sock);
extern int client_publish(nng_socket sock, const char *topic, uint8_t *payload,
    uint32_t len, bool dup, uint8_t qos, bool retain);

#endif // NANOMQ_BRIDGE_H