#ifndef MQTT_UNSUBSCRIBE_HANDLE_H
#define MQTT_UNSUBSCRIBE_HANDLE_H

#include <nng/nng.h>
#include "include/packet.h"
#include "apps/broker.h"

uint8_t decode_unsub_message(nng_msg *, packet_unsubscribe *);
uint8_t encode_unsuback_message(nng_msg *, packet_unsubscribe *);
uint8_t unsub_ctx_handle(emq_work *);

#endif // MQTT_UNSUBSCRIBE_HANDLE_H

