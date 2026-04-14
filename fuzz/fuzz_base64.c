#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "nng/supplemental/nanolib/base64.h"
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char *enc_out = NULL;
    unsigned char *dec_out = NULL;
    if (size > 0) {
        unsigned int enc_sz = BASE64_ENCODE_OUT_SIZE(size);
        enc_out = (char *)malloc(enc_sz);
        if (enc_out) {
            base64_encode(data, (unsigned int)size, enc_out);
        }
    }
    if (size > 0) {
        unsigned int dec_sz = BASE64_DECODE_OUT_SIZE(size);
        dec_out = (unsigned char *)malloc(dec_sz);
        if (dec_out) {
            base64_decode((const char *)data, (unsigned int)size, dec_out);
        }
    }
    free(enc_out);
    free(dec_out);
    return 0;
}
