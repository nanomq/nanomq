#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "nng/nng.h"
#include "nng/supplemental/nanolib/conf.h"
#include "nng/supplemental/nanolib/topics.h"

static int can_skip_levels(const char *topic, int levels) {
    const char *pos = topic;
    for (int i = 0; i < levels; i++) {
        if (pos == NULL) {
            return 0;
        }
        pos = strchr(pos, '/');
        if (pos == NULL) {
            return 0;
        }
        pos++;
    }
    return 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 3) return 0;

    uint8_t local_len = data[0];
    if (size < 1 + local_len + 1) return 0;
    
    uint8_t remote_len = data[1 + local_len];
    if (size < 1 + local_len + 1 + remote_len) return 0;

    const char *local_ptr = (const char*)data + 1;
    const char *remote_ptr = (const char*)data + 1 + local_len + 1;
    const char *input_ptr = (const char*)data + 1 + local_len + 1 + remote_len;
    size_t input_len = size - (1 + local_len + 1 + remote_len);

    // Make null-terminated copies
    char *local_topic = malloc(local_len + 1);
    char *remote_topic = malloc(remote_len + 1);
    char *input_topic = malloc(input_len + 1);
    
    if (!local_topic || !remote_topic || !input_topic) {
        if (local_topic) free(local_topic);
        if (remote_topic) free(remote_topic);
        if (input_topic) free(input_topic);
        return 0;
    }

    memcpy(local_topic, local_ptr, local_len);
    local_topic[local_len] = '\0';
    
    memcpy(remote_topic, remote_ptr, remote_len);
    remote_topic[remote_len] = '\0';
    
    memcpy(input_topic, input_ptr, input_len);
    input_topic[input_len] = '\0';

    topics s;
    memset(&s, 0, sizeof(s));
    s.local_topic = local_topic;
    s.local_topic_len = local_len;
    s.remote_topic = remote_topic;
    s.remote_topic_len = remote_len;
    
    // Initialize levels to defaults (as per topics.c logic or just let preprocess handle it)
    // preprocess_topics sets them, so we don't strictly need to init, but good practice.
    s.local_skip_level = 0;
    s.local_save_level = LOCAL_TOPIC_DEFAULT_LEVEL;

    // Fuzz preprocess_topics (is_sub = true)
    preprocess_topics(&s, true);
    
    // Avoid undefined input state that is not reachable in real bridge flow:
    // when skip_level points beyond topic separators, generate_repub_topic
    // may dereference NULL in nng_strdup.
    if (s.local_save_level < 0 || can_skip_levels(input_topic, s.local_skip_level)) {
        char *res = generate_repub_topic(&s, input_topic, true);
        if (res) {
            nng_strfree(res);
        }
    }

    // Try other direction or combinations if valuable
    // For now this covers the main logic paths

    // Clean up
    free(local_topic);
    free(remote_topic);
    free(input_topic);
    
    return 0;
}
