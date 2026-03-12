#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "nng/nng.h"
#include "nng/protocol/mqtt/mqtt_parser.h"
#include "unsub_handler.h"
#include "broker.h"
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return 0;
    nng_msg *msg = NULL;
    if (nng_msg_alloc(&msg, 0) != 0) {
        return 0;
    }
    nng_msg_append(msg, data, size);
    nano_work work = {0};
    work.msg = msg;
    work.proto_ver = (data[0] % 2) ? MQTT_PROTOCOL_VERSION_v5 : MQTT_PROTOCOL_VERSION_v311;
    packet_unsubscribe unsubpkt = {0};
    work.unsub_pkt = &unsubpkt;
    decode_unsub_msg(&work);
    topic_node *tn = work.unsub_pkt->node;
    while (tn) {
        topic_node *next = tn->next;
        nng_free(tn, sizeof(topic_node));
        tn = next;
    }
    if (unsubpkt.prop_len > 0 && unsubpkt.properties) {
        property_free(unsubpkt.properties);
    }
    nng_msg_free(msg);
    return 0;
}
