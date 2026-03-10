#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "include/nanomq.h"
#include "include/pub_handler.h"
#include "nng/protocol/mqtt/mqtt.h"

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

    free_pub_packet(work->pub_packet);
    nng_free(work, sizeof(nano_work));
    nng_msg_free(msg);

    return 0;
}
