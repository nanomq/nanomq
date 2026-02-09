#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "nng/nng.h"
#include "nng/protocol/mqtt/mqtt.h"
#include "nng/protocol/mqtt/mqtt_parser.h"

// Fuzz MQTT packet decoding for both v3.1.1 and v5
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2 || size > 65536) {
        return 0;
    }

    nng_msg *msg = NULL;
    int rv = nng_mqtt_msg_alloc(&msg, 0);
    if (rv != 0) {
        return 0;
    }

    // Split input: first byte determines protocol version
    uint8_t proto_ver = data[0] % 2;  // 0 for v4, 1 for v5
    const uint8_t *packet_data = data + 1;
    size_t packet_size = size - 1;

    // Append data to message body
    if (nng_msg_append(msg, packet_data, packet_size) != 0) {
        nng_msg_free(msg);
        return 0;
    }

    // Test MQTT message decoding
    if (proto_ver == 1) {
        // MQTT v5
        nng_mqttv5_msg_decode(msg);
    } else {
        // MQTT v3.1.1/v4
        nng_mqtt_msg_decode(msg);
    }

    // Cleanup
    nng_msg_free(msg);
    return 0;
}
