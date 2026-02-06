/**
 * @file fuzz_exchange.c
 * @brief Fuzzer for NanoMQ exchange functionality
 * 
 * Tests:
 * - exchange_init: Initialize exchange with various configurations
 * - exchange_handle_msg: Handle messages with different keys
 * - exchange_release: Release exchange resources
 * - ringbuffer operations: Test FULL_NONE, FULL_RETURN, FULL_DROP modes
 * - message overflow: Test ringbuffer capacity limits
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "nng/nng.h"
#include "nng/exchange/exchange.h"
#include "nng/mqtt/mqtt_client.h"

#define UNUSED(x) ((void) x)

// Global state
static bool initialized = false;
static exchange_t *g_exchange = NULL;

// Helper: Free message list (from unit test)
static void free_msg_list(nng_msg **msgList, nng_msg *msg, int *lenp, int freeMsg) {
    if (!lenp) return;
    
    for (int i = 0; i < *lenp; i++) {
        if (freeMsg && msgList && msgList[i]) {
            nng_msg_free(msgList[i]);
        }
    }
    
    if (msg) {
        nng_msg_free(msg);
    }
    
    if (msgList) {
        nng_free(msgList, sizeof(nng_msg *) * (*lenp));
    }
    
    if (lenp) {
        nng_free(lenp, sizeof(int));
    }
}

// Helper: Allocate publish message (from unit test)
static nng_msg *alloc_pub_msg(const char *topic) {
    nng_msg *pubmsg;
    if (nng_mqtt_msg_alloc(&pubmsg, 0) != 0) {
        return NULL;
    }
    
    nng_mqtt_msg_set_packet_type(pubmsg, NNG_MQTT_PUBLISH);
    nng_mqtt_msg_set_publish_dup(pubmsg, 0);
    nng_mqtt_msg_set_publish_retain(pubmsg, 0);
    nng_mqtt_msg_set_publish_topic(pubmsg, topic);
    nng_mqtt_msg_set_publish_topic_len(pubmsg, strlen(topic));
    nng_mqtt_msg_encode(pubmsg);
    
    return pubmsg;
}

// Setup exchange with fuzzer-provided parameters
static int setup_exchange(unsigned int rb_cap, uint8_t fullOp, size_t rb_count) {
    if (g_exchange) {
        exchange_release(g_exchange);
        g_exchange = NULL;
    }
    
    // Allocate ringbuffer names
    char **ringBufferNames = nng_alloc(rb_count * sizeof(char *));
    if (!ringBufferNames) {
        return -1;
    }
    
    for (size_t i = 0; i < rb_count; i++) {
        ringBufferNames[i] = nng_alloc(100 * sizeof(char));
        if (!ringBufferNames[i]) {
            // Cleanup on error
            for (size_t j = 0; j < i; j++) {
                nng_free(ringBufferNames[j], 100 * sizeof(char));
            }
            nng_free(ringBufferNames, rb_count * sizeof(char *));
            return -1;
        }
        snprintf(ringBufferNames[i], 100, "ringBuffer%zu", i);
    }
    
    // Setup capacities and fullOps
    unsigned int *caps = nng_alloc(rb_count * sizeof(unsigned int));
    if (!caps) {
        for (size_t i = 0; i < rb_count; i++) {
            nng_free(ringBufferNames[i], 100 * sizeof(char));
        }
        nng_free(ringBufferNames, rb_count * sizeof(char *));
        return -1;
    }
    
    uint8_t *fullOps = nng_alloc(rb_count * sizeof(uint8_t));
    if (!fullOps) {
        nng_free(caps, rb_count * sizeof(unsigned int));
        for (size_t i = 0; i < rb_count; i++) {
            nng_free(ringBufferNames[i], 100 * sizeof(char));
        }
        nng_free(ringBufferNames, rb_count * sizeof(char *));
        return -1;
    }
    
    for (size_t i = 0; i < rb_count; i++) {
        caps[i] = rb_cap;
        fullOps[i] = fullOp;
    }
    
    // Initialize exchange
    int rv = exchange_init(&g_exchange, "fuzz_exchange", "fuzz_topic", 
                          0, 0, caps, ringBufferNames, fullOps, rb_count);
    
    // Cleanup
    for (size_t i = 0; i < rb_count; i++) {
        nng_free(ringBufferNames[i], 100 * sizeof(char));
    }
    nng_free(ringBufferNames, rb_count * sizeof(char *));
    nng_free(caps, rb_count * sizeof(unsigned int));
    nng_free(fullOps, rb_count * sizeof(uint8_t));
    
    if (rv == 0) {
        initialized = true;
    }
    
    return rv;
}

// Test: exchange_init with various parameters
static void fuzz_test_exchange_init(unsigned int cap, uint8_t fullOp, size_t rb_count) {
    // Limit rb_count to prevent OOM
    if (rb_count > 10) rb_count = 10;
    if (rb_count == 0) rb_count = 1;
    
    // Limit capacity to prevent OOM
    if (cap > 10000) cap = 10000;
    if (cap == 0) cap = 1;
    
    setup_exchange(cap, fullOp, rb_count);
}

// Test: exchange_handle_msg
static void fuzz_test_handle_msg(uint64_t key, const char *topic, bool use_aio) {
    if (!g_exchange) return;
    
    nng_msg *msg = alloc_pub_msg(topic);
    if (!msg) return;
    
    nng_aio *aio = NULL;
    if (use_aio) {
        if (nng_aio_alloc(&aio, NULL, NULL) != 0) {
            nng_msg_free(msg);
            return;
        }
        nng_aio_begin(aio);
    }
    
    int rv = exchange_handle_msg(g_exchange, key, (void *)msg, aio);
    
    // ✅ FIX: If exchange_handle_msg failed, free the message
    if (rv != 0) {
        nng_msg_free(msg);
    }
    
    if (use_aio && aio) {
        if (rv == 0) {
            // Check if ringbuffer returned messages (when full)
            nng_msg **msgList = nng_aio_get_prov_data(aio);
            nng_msg *ret_msg = nng_aio_get_msg(aio);
            
            if (msgList && ret_msg) {
                int *listLen = nng_msg_get_proto_data(ret_msg);
                if (listLen) {
                    free_msg_list(msgList, ret_msg, listLen, 1);
                }
            }
        }
        
        nng_aio_finish(aio, 0);
        nng_aio_free(aio);
    }
}

// Test: Fill ringbuffer to capacity
static void fuzz_test_ringbuffer_fill(uint64_t start_key, uint32_t count, const char *topic) {
    if (!g_exchange) return;
    
    // Limit count to prevent hanging
    if (count > 1000) count = 1000;
    
    for (uint32_t i = 0; i < count; i++) {
        nng_msg *msg = alloc_pub_msg(topic);
        if (!msg) continue;
        
        int rv = exchange_handle_msg(g_exchange, start_key + i, (void *)msg, NULL);
        
        // ✅ FIX: If exchange_handle_msg failed, free the message
        if (rv != 0) {
            nng_msg_free(msg);
        }
    }
}

// Test: Ringbuffer overflow with AIO
static void fuzz_test_ringbuffer_overflow(uint64_t start_key, const char *topic) {
    if (!g_exchange) return;
    
    // First fill the ringbuffer
    for (uint32_t i = 0; i < 100; i++) {
        nng_msg *msg = alloc_pub_msg(topic);
        if (!msg) continue;
        
        int rv = exchange_handle_msg(g_exchange, start_key + i, (void *)msg, NULL);
        
        // ✅ FIX: If failed, free the message
        if (rv != 0) {
            nng_msg_free(msg);
        }
    }
    
    // Now trigger overflow with AIO
    nng_aio *aio = NULL;
    if (nng_aio_alloc(&aio, NULL, NULL) != 0) {
        return;
    }
    
    nng_aio_begin(aio);
    
    nng_msg *msg = alloc_pub_msg(topic);
    if (msg) {
        int rv = exchange_handle_msg(g_exchange, start_key + 100, (void *)msg, aio);
        
        // ✅ FIX: If failed, free the message
        if (rv != 0) {
            nng_msg_free(msg);
        } else {
            nng_msg **msgList = nng_aio_get_prov_data(aio);
            nng_msg *ret_msg = nng_aio_get_msg(aio);
            
            if (msgList && ret_msg) {
                int *listLen = nng_msg_get_proto_data(ret_msg);
                if (listLen) {
                    free_msg_list(msgList, ret_msg, listLen, 1);
                }
            }
        }
    }
    
    nng_aio_finish(aio, 0);
    nng_aio_free(aio);
}

// Test: exchange_release
static void fuzz_test_exchange_release(void) {
    if (g_exchange) {
        exchange_release(g_exchange);
        g_exchange = NULL;
        initialized = false;
    }
}

// Test: Invalid parameters to exchange_init
static void fuzz_test_invalid_init(void) {
    exchange_t *ex = NULL;
    char **ringBufferNames = NULL;
    unsigned int caps = 10;
    uint8_t fullOps = RB_FULL_NONE;
    
    // Test NULL exchange pointer
    int rv = exchange_init(NULL, NULL, "topic", 0, 0, &caps, ringBufferNames, &fullOps, 1);
    (void)rv;  // Expected to fail
    
    // Test NULL name
    rv = exchange_init(&ex, NULL, "topic", 0, 0, &caps, ringBufferNames, &fullOps, 1);
    (void)rv;  // Expected to fail
    
    if (ex) {
        exchange_release(ex);
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8) return 0;
    if (size > 4096) size = 4096;
    
    // Extract test mode and parameters
    uint8_t mode = data[0];
    uint8_t fullOp = data[1] % 3;  // RB_FULL_NONE=0, FULL_RETURN=1, FULL_DROP=2
    
    uint32_t rb_cap = 0;
    uint32_t rb_count = 0;
    uint64_t key = 0;
    
    if (size >= 4) {
        rb_cap = data[2] | (data[3] << 8);
        // Limit capacity
        if (rb_cap == 0) rb_cap = 10;
        if (rb_cap > 1000) rb_cap = 1000;
    }
    
    if (size >= 5) {
        rb_count = (data[4] % 5) + 1;  // 1-5 ringbuffers
    }
    
    if (size >= 13) {
        memcpy(&key, data + 5, sizeof(uint64_t));
    }
    
    // Extract topic from remaining data
    char topic[256] = "fuzz_topic";
    if (size > 13) {
        size_t topic_len = size - 13;
        if (topic_len > 255) topic_len = 255;
        memcpy(topic, data + 13, topic_len);
        topic[topic_len] = '\0';
        
        // Ensure valid string (no null bytes in middle)
        for (size_t i = 0; i < topic_len; i++) {
            if (topic[i] == '\0') {
                topic[i] = '_';
            }
        }
    }
    
    // Test mode selection
    if (mode & 0x10) {
        rb_count = 1;
    }

    if ((mode & 0x01) || (mode & 0x10)) {
        // Test: Initialize exchange with fuzzer params
        fuzz_test_exchange_init(rb_cap, fullOp, rb_count);
    }
    
    if (mode & 0x02) {
        // Test: Handle single message without AIO
        fuzz_test_handle_msg(key, topic, false);
    }
    
    if (mode & 0x04) {
        // Test: Handle single message with AIO
        fuzz_test_handle_msg(key, topic, true);
    }
    
    if (mode & 0x08) {
        // Test: Fill ringbuffer
        uint32_t count = rb_cap;
        if (count > 100) count = 100;
        fuzz_test_ringbuffer_fill(key, count, topic);
    }
    
    if (mode & 0x10) {
        // Test: Ringbuffer overflow
        fuzz_test_ringbuffer_overflow(key, topic);
    }
    
    if (mode & 0x20) {
        // Test: Release exchange
        fuzz_test_exchange_release();
    }
    
    if (mode & 0x40) {
        // Test: Invalid init parameters
        fuzz_test_invalid_init();
    }
    
    if (mode & 0x80) {
        // Test: Multiple rapid operations
        for (int i = 0; i < 5; i++) {
            fuzz_test_handle_msg(key + i, topic, (i % 2) == 0);
        }
    }
    
    return 0;
}

// Cleanup on exit
__attribute__((destructor))
static void cleanup_fuzzer(void) {
    if (g_exchange) {
        exchange_release(g_exchange);
        g_exchange = NULL;
    }
}