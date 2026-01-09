#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "nng/supplemental/nanolib/conf.h"
#include "nng/supplemental/nanolib/cvector.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > 4096) {
        return 0;
    }

    // Allocate buffer with null terminator
    char *buf = (char *)malloc(size + 1);
    if (!buf) {
        return 0;
    }
    memcpy(buf, data, size);
    buf[size] = '\0';

    // Initialize a minimal conf_rule structure
    conf_rule cr;
    memset(&cr, 0, sizeof(conf_rule));
    cr.rules = NULL;

    // Test SQL parsing
    rule_sql_parse(&cr, buf);

    // Cleanup: free any allocated rules
    if (cr.rules) {
        for (size_t i = 0; i < cvector_size(cr.rules); i++) {
            rule_free(&cr.rules[i]);
        }
        cvector_free(cr.rules);
    }

    free(buf);
    return 0;
}
