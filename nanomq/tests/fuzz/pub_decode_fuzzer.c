#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "include/nanomq.h"
#include "include/pub_handler.h"

// suppress logging
int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc;
    (void)argv;
    log_set_level(NNG_LOG_FATAL);
    log_clear_callback();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 3) {
        return 0;
    }

    // first byte to determine MQTT version
    uint8_t proto_ver = (data[0] % 2 == 0) ? MQTT_PROTOCOL_VERSION_v311 : MQTT_PROTOCOL_VERSION_v5;
    
    // second byte to determine how many bytes to put in the header (1-5)
    size_t header_len = (data[1] % 5) + 1;
    
    if (size < 2 + header_len) {
        return 0;
    }

    const uint8_t *header_data = data + 2;
    const uint8_t *body_data = data + 2 + header_len;
    size_t body_len = size - (2 + header_len);

    // initialize nano_work
    nano_work *work = nng_zalloc(sizeof(*work));
    if (work == NULL) {
        return 0;
    }
    work->proto_ver = proto_ver;

    // initialize pub_packet
    work->pub_packet = nng_zalloc(sizeof(struct pub_packet_struct));
    if (work->pub_packet == NULL) {
        nng_free(work, sizeof(*work));
        return 0;
    }

    // initialize nng_msg
    nng_msg *msg = NULL;
    if (nng_msg_alloc(&msg, 0) != 0) {
        nng_free(work->pub_packet, sizeof(struct pub_packet_struct));
        nng_free(work, sizeof(*work));
        return 0;
    }
    work->msg = msg;

    // header and body
    nng_msg_header_append(msg, header_data, header_len);
    if (body_len > 0) {
        nng_msg_append(msg, body_data, body_len);
    }

    // call the target function
    decode_pub_message(work, proto_ver);

    // cleanup
    free_pub_packet(work->pub_packet);
    nng_msg_free(msg);
    nng_free(work, sizeof(*work));

    return 0;
}
