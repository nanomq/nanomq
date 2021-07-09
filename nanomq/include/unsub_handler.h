#ifndef MQTT_UNSUBSCRIBE_HANDLE_H
#define MQTT_UNSUBSCRIBE_HANDLE_H

#include <nng/nng.h>

#include "broker.h"
#include "packet.h"

uint8_t decode_unsub_message(nano_work *);
uint8_t encode_unsuback_message(nng_msg *, nano_work *);
uint8_t unsub_ctx_handle(nano_work *);
void    destroy_unsub_ctx(packet_unsubscribe *);

#endif // MQTT_UNSUBSCRIBE_HANDLE_H
