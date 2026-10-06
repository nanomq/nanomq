#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "nng/supplemental/nanolib/nmq_base64.h"
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char *enc_out = NULL;
    unsigned char *dec_out = NULL;
    if (size > 0) {
        size_t enc_sz = BASE64_ENCODE_OUT_SIZE(size);
        enc_out = (char *)malloc(enc_sz);
        if (enc_out) {
            nmq_base64_encode(data, size, enc_out, enc_sz);
        }
    }
    if (size > 0) {
        size_t dec_sz = BASE64_DECODE_OUT_SIZE(size);
        dec_out = (unsigned char *)malloc(dec_sz);
        if (dec_out) {
            nmq_base64_decode((const char *)data, size, dec_out, dec_sz);
        }
    }
    free(enc_out);
    free(dec_out);
    return 0;
}
