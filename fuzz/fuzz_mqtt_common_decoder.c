#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "nng/nng.h"
#include "nng/protocol/mqtt/mqtt_parser.h"
#include "mqtt_api.h"
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 5) return 0;
    size_t remain = size - 1;
    size_t hlen = remain / 3;
    size_t blen = remain / 3;
    size_t clen = remain - hlen - blen;
    nng_msg *src = NULL;
    if (nng_msg_alloc(&src, 0) != 0) {
        return 0;
    }
    nng_msg_append_u32(src, (uint32_t)hlen);
    nng_msg_append(src, data + 1, hlen);
    nng_msg_append_u32(src, (uint32_t)blen);
    nng_msg_append(src, data + 1 + hlen, blen);
    nng_msg_append_u32(src, (uint32_t)clen);
    nng_msg_append(src, (const char *)(data + 1 + hlen + blen), clen);
    uint8_t verflag = data[0] % 2;
    uint8_t proto_ver = verflag ? MQTT_PROTOCOL_VERSION_v5 : MQTT_PROTOCOL_VERSION_v311;
    nng_msg_append(src, &proto_ver, 1);
    nng_msg *dest = NULL;
    decode_common_mqtt_msg(&dest, src);
    if (dest) {
        conn_param *cp = nng_msg_get_conn_param(dest);
        if (cp) {
            conn_param_free(cp);
            nng_msg_set_conn_param(dest, NULL);
        }
        nng_msg_free(dest);
    }
    return 0;
}
