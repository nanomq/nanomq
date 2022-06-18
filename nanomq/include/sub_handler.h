#ifndef MQTT_SUBSCRIBE_HANDLE_H
#define MQTT_SUBSCRIBE_HANDLE_H

#include <nng/nng.h>
#include <nng/mqtt/packet.h>

#include "broker.h"

int decode_sub_msg(nano_work *);
int encode_suback_msg(nng_msg *, nano_work *);
int sub_ctx_handle(nano_work *);
// free mem about one topic in sub_ctx
void del_sub_ctx(void *, char *);
// free all mem about sub_ctx
void destroy_sub_ctx(void *);
void destroy_sub_pkt(packet_subscribe *, uint8_t);
void destroy_sub_client(uint32_t pid, dbtree * db);

#endif
