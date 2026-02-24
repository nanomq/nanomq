#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "nftp.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    nftp *p = NULL;
    if (nftp_alloc(&p) != 0) {
        return 0;
    }

    if (size < 6) {
        nftp_free(p);
        return 0;
    }

    uint8_t *buffer = (uint8_t *)malloc(size);
    if (!buffer) {
        nftp_free(p);
        return 0;
    }
    memcpy(buffer, data, size);

    nftp_decode(p, buffer, size);

    free(buffer);
    nftp_free(p);
    return 0;
}
