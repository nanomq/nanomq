#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "nng/nng.h"
#include "nng/supplemental/http/http.h"
#include "supplemental/http/http_api.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > 65536) {
        return 0;
    }

    // Allocate a mutable buffer as the parser might modify it or require a non-const pointer
    void *buf = malloc(size);
    if (!buf) {
        return 0;
    }
    memcpy(buf, data, size);

    // Fuzz Request Parsing
    nni_http_req *req = NULL;
    if (nni_http_req_alloc(&req, NULL) == 0) {
        size_t used = 0;
        // nni_http_req_parse parses as much as possible from buf
        nni_http_req_parse(req, buf, size, &used);
        nni_http_req_free(req);
    }

    // Reset buffer for response parsing
    memcpy(buf, data, size);

    // Fuzz Response Parsing
    nni_http_res *res = NULL;
    if (nni_http_res_alloc(&res) == 0) {
        size_t used = 0;
        nni_http_res_parse(res, buf, size, &used);
        nni_http_res_free(res);
    }

    free(buf);
    return 0;
}
