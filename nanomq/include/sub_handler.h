#ifndef MQTT_SUBSCRIBE_HANDLE_H
#define MQTT_SUBSCRIBE_HANDLE_H

#include <nng/nng.h>
#include <nng/mqtt/packet.h>

#include "broker.h"

uint8_t decode_sub_message(nano_work *);
uint8_t encode_suback_message(nng_msg *, nano_work *);
uint8_t sub_ctx_handle(nano_work *);
// free mem about one topic in sub_ctx
void del_sub_ctx(void *, char *);
// free all mem about sub_ctx
void destroy_sub_ctx(void *);
void destroy_sub_pkt(packet_subscribe *, uint8_t);
void init_sub_property(packet_subscribe *);

// functions about clean session
int  cache_session(char *, conn_param *, uint32_t, void *);
int  restore_session(char *, conn_param *, uint32_t, void *);

#endif
