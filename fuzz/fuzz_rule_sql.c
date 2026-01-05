#include <stdint.h>
#include <stddef.h>
#include "nanomq_rule.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > 4096) {
        return 0;
    }

    char buf[4097];
    memcpy(buf, data, size);
    buf[size] = '\0';

    // 只 fuzz 解析，不启动 broker
    rule_sql_parse(buf);

    return 0;
}
