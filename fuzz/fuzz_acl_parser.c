#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "core/strs.h"
#include "nng/supplemental/nanolib/acl_conf.h"
#include "nng/supplemental/nanolib/cJSON.h"

void nni_free(void *, size_t);

// Fuzz ACL rule JSON parser
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > 16384) {
        return 0;
    }

    // Create null-terminated string
    char *input = (char *)malloc(size + 1);
    if (!input) {
        return 0;
    }
    memcpy(input, data, size);
    input[size] = '\0';

    // Parse as JSON
    cJSON *json = cJSON_Parse(input);
    if (json) {
        acl_rule *rule = NULL;
        
        // Test ACL rule parsing
        if (cJSON_IsObject(json)) {
            acl_parse_json_rule(json, 0, &rule);
            
            // Cleanup rule if allocated
            if (rule) {
                // Free rule components
                if (rule->rule_type != ACL_AND && rule->rule_type != ACL_OR) {
                    if (rule->rule_ct.ct.type == ACL_RULE_SINGLE_STRING && 
                        rule->rule_ct.ct.value.str) {
                        nni_strfree(rule->rule_ct.ct.value.str);
                    } else if (rule->rule_ct.ct.type == ACL_RULE_STRING_ARRAY) {
                        for (size_t i = 0; i < rule->rule_ct.ct.count; i++) {
                            if (rule->rule_ct.ct.value.str_array[i]) {
                                nni_strfree(rule->rule_ct.ct.value.str_array[i]);
                            }
                        }
                        if (rule->rule_ct.ct.value.str_array) {
                            nni_free(rule->rule_ct.ct.value.str_array,
                                rule->rule_ct.ct.count * sizeof(char *));
                        }
                    }
                } else {
                    // Free AND/OR subrules
                    acl_sub_rules_array *array = &rule->rule_ct.array;
                    for (size_t i = 0; i < array->count; i++) {
                        acl_sub_rule *sub = array->rules[i];
                        if (sub) {
                            if (sub->rule_ct.type == ACL_RULE_SINGLE_STRING &&
                                sub->rule_ct.value.str) {
                                nni_strfree(sub->rule_ct.value.str);
                            } else if (sub->rule_ct.type == ACL_RULE_STRING_ARRAY) {
                                for (size_t j = 0; j < sub->rule_ct.count; j++) {
                                    if (sub->rule_ct.value.str_array[j]) {
                                        nni_strfree(sub->rule_ct.value.str_array[j]);
                                    }
                                }
                                if (sub->rule_ct.value.str_array) {
                                    nni_free(sub->rule_ct.value.str_array,
                                        sub->rule_ct.count * sizeof(char *));
                                }
                            }
                            nni_free(sub, sizeof(acl_sub_rule));
                        }
                    }
                    if (array->rules) {
                        nni_free(array->rules, sizeof(acl_sub_rule *) * array->count);
                    }
                }
                
                // Free topics
                for (size_t i = 0; i < rule->topic_count; i++) {
                    if (rule->topics[i]) {
                        nni_strfree(rule->topics[i]);
                    }
                }
                if (rule->topics) {
                    nni_free(rule->topics, rule->topic_count * sizeof(char *));
                }
                
                nni_free(rule, sizeof(acl_rule));
            }
        }
        
        cJSON_Delete(json);
    }

    free(input);
    return 0;
}
