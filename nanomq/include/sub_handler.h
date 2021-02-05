#ifndef MQTT_SUBSCRIBE_HANDLE_H
#define MQTT_SUBSCRIBE_HANDLE_H

#include <nng/nng.h>
#include "include/packet.h"
#include "apps/broker.h"

uint8_t decode_sub_message(emq_work *);
uint8_t encode_suback_message(nng_msg *, emq_work *);
uint8_t sub_ctx_handle(emq_work *);
void del_sub_ctx(void *, char *);
void destroy_sub_ctx(void *);
void del_sub_pipe_id(uint32_t);
void del_sub_client_id(char *);
void init_sub_property(packet_subscribe *);

#endif
