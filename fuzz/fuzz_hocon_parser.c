#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "nng/supplemental/nanolib/hocon.h"
#include "nng/supplemental/nanolib/cJSON.h"

// Fuzz HOCON configuration parser
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > 32768) {
        return 0;
    }

    // Create null-terminated string
    char *input = (char *)malloc(size + 1);
    if (!input) {
        return 0;
    }
    memcpy(input, data, size);
    input[size] = '\0';

    // Test HOCON string parsing
    cJSON *parsed = hocon_parse_str(input, size);
    
    // Cleanup
    if (parsed) {
        cJSON_Delete(parsed);
    }

    free(input);
    return 0;
}
