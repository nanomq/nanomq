#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "include/nanomq.h"
#include "include/pub_handler.h"
#include "nng/protocol/mqtt/mqtt.h"
#include "nng/mqtt/mqtt_client.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return 0;

    uint8_t proto_ver = (data[0] % 2 == 0) ? MQTT_PROTOCOL_VERSION_v311 : MQTT_PROTOCOL_VERSION_v5;
    const uint8_t *msg_data = data + 1;
    size_t msg_size = size - 1;

    nng_msg *msg = NULL;
    if (nng_msg_alloc(&msg, 0) != 0) {
        return 0;
    }

    if (msg_size < 2) {
        nng_msg_free(msg);
        return 0;
    }

    if (nng_msg_append(msg, msg_data, msg_size) != 0) {
        nng_msg_free(msg);
        return 0;
    }

    size_t bytes_to_move = 0;
    if (msg_size > 0) {
        bytes_to_move++;
        for (int i = 1; i < 5 && i < msg_size; i++) {
             bytes_to_move++;
             if ((msg_data[i] & 0x80) == 0) break;
        }
    }

    if (bytes_to_move > 0) {
        nng_msg_header_append(msg, msg_data, bytes_to_move);
        nng_msg_trim(msg, bytes_to_move);
    }

    nano_work *work = nng_alloc(sizeof(nano_work));
    if (!work) {
        nng_msg_free(msg);
        return 0;
    }
    memset(work, 0, sizeof(nano_work));

    work->msg = msg;
    work->pub_packet = nng_zalloc(sizeof(struct pub_packet_struct));
    if (!work->pub_packet) {
        nng_free(work, sizeof(nano_work));
        nng_msg_free(msg);
        return 0;
    }

    decode_pub_message(work, proto_ver);

    if (proto_ver == MQTT_PROTOCOL_VERSION_v5 && work->pub_packet) {
        uint8_t pkt_type = work->pub_packet->fixed_header.packet_type;
        if (pkt_type == PUBLISH) {
            if (work->pub_packet->var_header.publish.properties) {
                mqtt_property_free(work->pub_packet->var_header.publish.properties);
                work->pub_packet->var_header.publish.properties = NULL;
                work->pub_packet->var_header.publish.prop_len = 0;
            }
        } else if (pkt_type == PUBACK || pkt_type == PUBREC ||
                   pkt_type == PUBREL || pkt_type == PUBCOMP) {
            if (work->pub_packet->var_header.pub_arrc.properties) {
                mqtt_property_free(work->pub_packet->var_header.pub_arrc.properties);
                work->pub_packet->var_header.pub_arrc.properties = NULL;
                work->pub_packet->var_header.pub_arrc.prop_len = 0;
            }
        }
    }

    free_pub_packet(work->pub_packet);
    nng_free(work, sizeof(nano_work));
    nng_msg_free(msg);

    return 0;
}
