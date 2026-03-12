#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "nng/nng.h"
#include "nng/mqtt/mqtt_client.h"
#include "nng/protocol/mqtt/mqtt_parser.h"
#include "sub_handler.h"
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
    packet_subscribe subpkt = {0};
    work.sub_pkt = &subpkt;
    decode_sub_msg(&work);
    if (work.sub_pkt->properties) {
        mqtt_property_free(work.sub_pkt->properties);
        work.sub_pkt->properties = NULL;
        work.sub_pkt->prop_len = 0;
    }
    topic_node *tn = work.sub_pkt->node;
    while (tn) {
        topic_node *next = tn->next;
        if (tn->topic.body && tn->topic.len > 0) {
            nng_free(tn->topic.body, tn->topic.len + 1);
        }
        nng_free(tn, sizeof(topic_node));
        tn = next;
    }
    nng_msg_free(msg);
    return 0;
}
