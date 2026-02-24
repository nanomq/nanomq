#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "l8w8jwt/decode.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;
    char *jwt = (char *)malloc(size + 1);
    if (!jwt) return 0;
    memcpy(jwt, data, size);
    jwt[size] = '\0';

    struct l8w8jwt_decoding_params params;
    l8w8jwt_decoding_params_init(&params);

    params.alg = L8W8JWT_ALG_RS256;
    params.jwt = jwt;
    params.jwt_length = size;

    uint8_t dummy_key[] = "-----BEGIN PUBLIC KEY-----\n"
                          "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvvXU\n"
                          "-----END PUBLIC KEY-----";
    params.verification_key = dummy_key;
    params.verification_key_length = sizeof(dummy_key);
    params.validate_exp = 0;
    params.validate_iat = 0;

    enum l8w8jwt_validation_result validation_result = 0;
    struct l8w8jwt_claim *claims = NULL;
    size_t claim_count = 0;

    l8w8jwt_decode(&params, &validation_result, &claims, &claim_count);

    if (claim_count > 0 && claims != NULL) {
        l8w8jwt_free_claims(claims, claim_count);
    }
    free(jwt);
    return 0;
}
