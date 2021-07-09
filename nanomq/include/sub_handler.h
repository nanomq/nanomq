#ifndef MQTT_SUBSCRIBE_HANDLE_H
#define MQTT_SUBSCRIBE_HANDLE_H

#include <nng/nng.h>
#include <packet.h>

#include "broker.h"

uint8_t decode_sub_message(nano_work *);
uint8_t encode_suback_message(nng_msg *, nano_work *);
uint8_t sub_ctx_handle(nano_work *);
// free mem about one topic in sub_ctx
void del_sub_ctx(void *, char *);
// free all mem about sub_ctx
void destroy_sub_ctx(void *);
void init_sub_property(packet_subscribe *);

#endif
