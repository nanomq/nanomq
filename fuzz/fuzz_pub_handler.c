#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "include/nanomq.h"
#include "include/pub_handler.h"
#include "nng/protocol/mqtt/mqtt.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return 0;

    // Use the first byte to determine the protocol version (v3.1.1 or v5)
    uint8_t proto_ver = (data[0] % 2 == 0) ? MQTT_PROTOCOL_VERSION_v311 : MQTT_PROTOCOL_VERSION_v5;
    const uint8_t *msg_data = data + 1;
    size_t msg_size = size - 1;

    // Create a dummy nng_msg
    nng_msg *msg = NULL;
    if (nng_msg_alloc(&msg, 0) != 0) {
        return 0;
    }

    // Set header and body
    // For simplicity, we'll put some bytes in header and some in body to simulate a real packet
    // But decode_pub_message primarily looks at header for fixed header and body for variable header/payload
    // The splitting logic in nng is complex, so we'll just put everything in body for now 
    // and manually construct a fixed header if needed, OR we can try to use nng_mqtt_msg_decode first.
    // However, decode_pub_message expects the nng_msg to be already somewhat structured or at least have header/body accessible.
    // Let's put a minimal valid fixed header in msg header.
    
    if (msg_size < 2) {
        nng_msg_free(msg);
        return 0;
    }

    // Try to append data to message body
    if (nng_msg_append(msg, msg_data, msg_size) != 0) {
        nng_msg_free(msg);
        return 0;
    }

    // We need to manually set the header to contain the fixed header byte(s)
    // The first byte of input (after proto) is the fixed header first byte
    // The remaining length bytes follow.
    // But nng_msg_header is separate.
    // Let's move the first few bytes from body to header to simulate what the transport layer does.
    // A minimal MQTT packet has at least 2 bytes (type+flags, remaining length).
    
    // We can't easily know how many bytes are remaining length without parsing.
    // Let's just move 2 bytes to header for basic testing, or rely on decode_pub_message handling body-only if it does?
    // Looking at decode_pub_message:
    // pub_packet->fixed_header = *(struct fixed_header *) nng_msg_header(msg);
    // It reads directly from header. So we MUST populate the header.
    
    // Let's take the first byte as type/flags, and next 1-4 bytes as varint remaining length.
    // We'll just move up to 5 bytes to header.
    size_t header_len = 0;
    if (msg_size >= 1) header_len++;
    if (msg_size >= 2) header_len++; // 1 byte RL
    // For fuzzing, we can just move a random amount, say up to 5 bytes, to header.
    // But to be effective, we should try to match the RL structure.
    
    // Simple heuristic: move up to 5 bytes, stopping if we see a byte with MSB 0 (end of varint)
    size_t bytes_to_move = 0;
    if (msg_size > 0) {
        bytes_to_move++; // Type/Flags
        for (int i = 1; i < 5 && i < msg_size; i++) {
             bytes_to_move++;
             if ((msg_data[i] & 0x80) == 0) break;
        }
    }

    if (bytes_to_move > 0) {
        nng_msg_header_append(msg, msg_data, bytes_to_move);
        nng_msg_trim(msg, bytes_to_move); // Remove from body
    }

    // Prepare nano_work
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

    // Call the target function
    decode_pub_message(work, proto_ver);

    // Cleanup
    free_pub_packet(work->pub_packet);
    nng_free(work->pub_packet, sizeof(struct pub_packet_struct));
    nng_free(work, sizeof(nano_work));
    nng_msg_free(msg);

    return 0;
}
