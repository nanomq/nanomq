#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "nng/supplemental/nanolib/cJSON.h"

// Fuzz REST API JSON request processing
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > 65536) {
        return 0;
    }

    // Create null-terminated string
    char *input = (char *)malloc(size + 1);
    if (!input) {
        return 0;
    }
    memcpy(input, data, size);
    input[size] = '\0';

    // Test JSON parsing with length
    cJSON *json = cJSON_ParseWithLength(input, size);
    
    if (json) {
        // Test various JSON operations that REST API uses
        
        // Test object queries
        cJSON *rawsql = cJSON_GetObjectItem(json, "rawsql");
        cJSON *actions = cJSON_GetObjectItem(json, "actions");
        cJSON *enabled = cJSON_GetObjectItem(json, "enabled");
        cJSON *params = cJSON_GetObjectItem(json, "params");
        
        // Test array iteration
        if (cJSON_IsArray(actions)) {
            cJSON *action = NULL;
            cJSON_ArrayForEach(action, actions) {
                if (cJSON_IsObject(action)) {
                    cJSON *name = cJSON_GetObjectItem(action, "name");
                    cJSON *action_params = cJSON_GetObjectItem(action, "params");
                    
                    // Test string value extraction
                    if (cJSON_IsString(name)) {
                        const char *name_str = cJSON_GetStringValue(name);
                        (void)name_str;  // Use the value
                    }
                    
                    // Test nested object iteration
                    if (cJSON_IsObject(action_params)) {
                        cJSON *param = NULL;
                        cJSON_ArrayForEach(param, action_params) {
                            if (cJSON_IsString(param)) {
                                const char *value = cJSON_GetStringValue(param);
                                (void)value;
                            }
                        }
                    }
                }
            }
        }
        
        // Test string value extraction
        if (cJSON_IsString(rawsql)) {
            const char *sql_str = cJSON_GetStringValue(rawsql);
            (void)sql_str;
        }
        
        // Test boolean extraction
        if (enabled) {
            bool enabled_val = cJSON_IsTrue(enabled);
            (void)enabled_val;
        }
        
        // Test number extraction
        cJSON *num_field = cJSON_GetObjectItem(json, "qos");
        if (cJSON_IsNumber(num_field)) {
            int qos_val = num_field->valueint;
            (void)qos_val;
        }
        
        // Test creating response (common pattern in REST API)
        cJSON *response = cJSON_CreateObject();
        if (response) {
            cJSON_AddNumberToObject(response, "code", 0);
            cJSON_AddStringToObject(response, "message", "test");
            cJSON_AddBoolToObject(response, "success", true);
            
            // Test serialization
            char *json_str = cJSON_PrintUnformatted(response);
            if (json_str) {
                cJSON_free(json_str);
            }
            
            cJSON_Delete(response);
        }
        
        cJSON_Delete(json);
    }

    free(input);
    return 0;
}
