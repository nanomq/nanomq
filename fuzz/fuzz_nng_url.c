#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "nng/nng.h"
#include "core/nng_impl.h"
#include "core/url.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > 4096) {
        return 0;
    }

    // Keep this target focused on URL parser logic for textual URLs.
    for (size_t i = 0; i < size; i++) {
        if (data[i] < 0x20 || data[i] > 0x7e) {
            return 0;
        }
    }
    
    char *input = (char *)malloc(size + 1);
    if (!input) {
        return 0;
    }
    memcpy(input, data, size);
    input[size] = '\0';

    if (strstr(input, "://") == NULL) {
        free(input);
        return 0;
    }

    nni_url *url = NULL;
    int rv = nni_url_parse(&url, input);
    if (rv == 0 && url != NULL) {
        nni_url_free(url);
    }

    free(input);
    return 0;
}
