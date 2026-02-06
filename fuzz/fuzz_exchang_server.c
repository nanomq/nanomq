/**
 * @file fuzz_exchange_server.c
 * @brief Fuzzer for NanoMQ exchange server functionality
 * 
 * Tests:
 * - exchange_client_open
 * - client_publish (with various QoS, topics, payloads)
 * - exchange_client_get_msg_by_key
 * - exchange_client_get_msgs_by_key
 * - exchange_client_get_msgs_fuzz (fuzzy search)
 * - client_get_msgs (aio-based retrieval)
 * - ringbuffer overflow handling
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "nng/nng.h"
#include "core/nng_impl.h"
#include "nng/exchange/exchange_client.h"
#include "nng/exchange/exchange.h"
#include "nng/supplemental/nanolib/cvector.h"
#include "core/defs.h"

#define UNUSED(x) ((void) x)

// Global state
static bool initialized = false;
static nng_socket g_sock;
static conf_exchange_node *g_conf = NULL;

// Helper: Free message list (from unit test)
static void free_msg_list(nng_msg **msgList, nng_msg *msg, uint32_t *lenp, int freeMsg) {
    if (!lenp) return;
    
    for (uint32_t i = 0; i < *lenp; i++) {
        if (freeMsg && msgList && msgList[i]) {
            nng_msg_free(msgList[i]);
        }
    }

    if (msg != NULL) {
        nng_msg_free(msg);
    }
    if (msgList != NULL) {
        nng_free(msgList, sizeof(nng_msg *) * (*lenp));
    }
    if (lenp != NULL) {
        nng_free(lenp, sizeof(uint32_t));
    }
}

// Helper: Publish message (from unit test)
static void client_publish(nng_socket sock, const char *topic, uint64_t key, 
                          uint8_t *payload, uint32_t payload_len, uint8_t qos) {
    nng_msg *pubmsg;
    if (nng_mqtt_msg_alloc(&pubmsg, 0) != 0) {
        return;
    }

    uint8_t *header = nng_msg_header(pubmsg);
    *header = *header | CMD_PUBLISH;
    nng_mqtt_msg_set_packet_type(pubmsg, NNG_MQTT_PUBLISH);
    nng_mqtt_msg_set_publish_dup(pubmsg, 0);
    nng_mqtt_msg_set_publish_qos(pubmsg, qos);
    nng_mqtt_msg_set_publish_retain(pubmsg, 0);
    nng_mqtt_msg_set_publish_topic(pubmsg, topic);
    nng_mqtt_msg_set_publish_topic_len(pubmsg, strlen(topic));
    nng_mqtt_msg_set_publish_payload(pubmsg, (uint8_t *)payload, payload_len);
    
    nni_aio *aio = NULL;
    if (nng_aio_alloc(&aio, NULL, NULL) != 0) {
        nng_msg_free(pubmsg);
        return;
    }

    nng_msg_set_timestamp(pubmsg, key);
    nng_mqtt_msg_encode(pubmsg);
    nni_aio_set_msg(aio, pubmsg);

    nng_send_aio(sock, aio);
    nng_aio_wait(aio);

    uint32_t *lenp = NULL;
    nng_msg **msgList = (nng_msg **)nng_aio_get_prov_data(aio);
    nng_msg *msg = nng_aio_get_msg(aio);
    if (msgList != NULL && msg != NULL) {
        lenp = nng_msg_get_proto_data(msg);
        free_msg_list(msgList, msg, lenp, 1);
    }

    nng_aio_free(aio);
}

// Helper: Get messages by key range (from unit test)
static void client_get_msgs(nng_socket sock, uint64_t startKey, uint64_t endKey, 
                           uint32_t *lenp, nng_msg ***msgList) {
    nni_aio *aio = NULL;
    if (nng_aio_alloc(&aio, NULL, NULL) != 0) {
        return;
    }

    nng_msg *msg;
    nng_time *tss = NULL;
    if (nng_msg_alloc(&msg, 0) != 0) {
        nng_aio_free(aio);
        return;
    }

    if (endKey == 0) {
        nng_msg_set_timestamp(msg, startKey);
        nng_msg_set_proto_data(msg, NULL, NULL);
    } else {
        tss = nng_alloc(sizeof(nng_time) * 3);
        if (!tss) {
            nng_msg_free(msg);
            nng_aio_free(aio);
            return;
        }
        tss[0] = startKey;
        tss[1] = endKey;
        tss[2] = (nng_time)NULL;
        nng_msg_set_proto_data(msg, NULL, (void *)tss);
    }
    
    nni_aio_set_msg(aio, msg);
    nng_recv_aio(sock, aio);
    nng_aio_wait(aio);

    *msgList = (nng_msg **)nng_aio_get_msg(aio);
    *lenp = (uintptr_t)nng_aio_get_prov_data(aio);

    if (tss != NULL) {
        nng_free(tss, sizeof(nng_time) * 3);
    }

    nng_msg_free(msg);
    nng_aio_free(aio);
}

// Helper: Get and clean messages (from unit test)
static void client_get_and_clean_msgs(nng_socket sock, uint32_t *lenp, nng_msg ***msgList) {
    nni_aio *aio = NULL;
    if (nng_aio_alloc(&aio, NULL, NULL) != 0) {
        return;
    }

    nng_msg *msg;
    nng_time *tss = NULL;
    if (nng_msg_alloc(&msg, 0) != 0) {
        nng_aio_free(aio);
        return;
    }

    tss = nng_alloc(sizeof(nng_time) * 3);
    if (!tss) {
        nng_msg_free(msg);
        nng_aio_free(aio);
        return;
    }
    tss[2] = 1;
    nng_msg_set_proto_data(msg, NULL, (void *)tss);

    nni_aio_set_msg(aio, msg);
    nng_recv_aio(sock, aio);
    nng_aio_wait(aio);

    *msgList = (nng_msg **)nng_aio_get_msg(aio);
    *lenp = (uintptr_t)nng_aio_get_prov_data(aio);

    if (tss != NULL) {
        nng_free(tss, sizeof(nng_time) * 3);
    }

    nng_msg_free(msg);
    nng_aio_free(aio);
}

// Setup exchange server
static int setup_exchange_server(void) {
    if (initialized) return 0;
    
    nng_socket pair0_sock;
    if (nng_rep0_open(&pair0_sock) != 0) {
        return -1;
    }
    
    g_sock.data = &pair0_sock;
    
    if (nng_exchange_client_open(&g_sock) != 0) {
        nng_close(pair0_sock);
        return -1;
    }

    // Setup configuration
    g_conf = nng_alloc(sizeof(conf_exchange_node));
    if (!g_conf) {
        nng_close(pair0_sock);
        return -1;
    }
    
    g_conf->name = "fuzz_exchange";
    g_conf->topic = "fuzz_topic";
    
    // Setup ring buffer
    ringBuffer_node *rb_node = nng_alloc(sizeof(ringBuffer_node));
    if (!rb_node) {
        nng_free(g_conf, sizeof(conf_exchange_node));
        nng_close(pair0_sock);
        return -1;
    }
    
    rb_node->name = "fuzz_ringbuffer";
    rb_node->cap = 100;  // Larger capacity for fuzzing
    rb_node->fullOp = RB_FULL_NONE;
    
    g_conf->rbufs = NULL;
    cvector_push_back(g_conf->rbufs, rb_node);
    g_conf->rbufs_sz = cvector_size(g_conf->rbufs);
    
    if (nng_socket_set_ptr(g_sock, NNG_OPT_EXCHANGE_BIND, g_conf) != 0) {
        cvector_free(g_conf->rbufs);
        nng_free(rb_node, sizeof(ringBuffer_node));
        nng_free(g_conf, sizeof(conf_exchange_node));
        nng_close(pair0_sock);
        return -1;
    }
    
    initialized = true;
    return 0;
}

// Test: Publish messages
static void fuzz_test_publish(const uint8_t *data, size_t size, 
                              uint64_t key, uint8_t qos) {
    if (size == 0) return;
    
    // Limit payload size
    size_t payload_len = (size > 256) ? 256 : size;
    
    // Create payload buffer
    uint8_t *payload = (uint8_t *)malloc(payload_len);
    if (!payload) return;
    
    memcpy(payload, data, payload_len);
    
    // Publish with fuzzer-provided data
    client_publish(g_sock, g_conf->topic, key, payload, payload_len, qos);
    
    free(payload);
}

// Test: Get message by single key
static void fuzz_test_get_msg_by_key(uint64_t key) {
    nni_sock *nsock = NULL;
    
    if (nni_sock_find(&nsock, g_sock.id) != 0 || !nsock) {
        return;
    }
    
    nni_msg *msg = NULL;
    int rv = exchange_client_get_msg_by_key(nni_sock_proto_data(nsock), key, &msg);
    
    // Message is just a pointer, don't free it here
    (void)rv;
    
    nni_sock_rele(nsock);
}

// Test: Get messages by key range
static void fuzz_test_get_msgs_by_key(uint64_t key, uint32_t count) {
    nni_sock *nsock = NULL;
    
    if (nni_sock_find(&nsock, g_sock.id) != 0 || !nsock) {
        return;
    }
    
    if (count > 100) count = 100;  // Limit to prevent OOM
    
    nng_msg **msgList = NULL;
    int rv = exchange_client_get_msgs_by_key(
        nni_sock_proto_data(nsock), key, count, &msgList);
    
    if (rv == 0 && msgList) {
        uint32_t *lenp = nng_alloc(sizeof(uint32_t));
        if (lenp) {
            *lenp = count;
            free_msg_list(msgList, NULL, lenp, 0);
        }
    }
    
    nni_sock_rele(nsock);
}

// Test: Fuzzy search
static void fuzz_test_get_msgs_fuzz(uint64_t startKey, uint64_t endKey) {
    nni_sock *nsock = NULL;
    
    if (nni_sock_find(&nsock, g_sock.id) != 0 || !nsock) {
        return;
    }
    
    nng_msg **msgList = NULL;
    uint32_t *lenp = nng_alloc(sizeof(uint32_t));
    if (!lenp) {
        nni_sock_rele(nsock);
        return;
    }
    
    int rv = exchange_client_get_msgs_fuzz(
        nni_sock_proto_data(nsock), startKey, endKey, lenp, &msgList);
    
    if (rv == 0 && msgList) {
        free_msg_list(msgList, NULL, lenp, 0);
    } else {
        nng_free(lenp, sizeof(uint32_t));
    }
    
    nni_sock_rele(nsock);
}

// Test: AIO-based message retrieval
static void fuzz_test_client_get_msgs(uint64_t startKey, uint64_t endKey) {
    uint32_t *lenp = nng_alloc(sizeof(uint32_t));
    if (!lenp) return;
    
    *lenp = 0;
    nng_msg **msgList = NULL;
    
    client_get_msgs(g_sock, startKey, endKey, lenp, &msgList);
    
    if (*lenp > 0 && msgList) {
        free_msg_list(msgList, NULL, lenp, 0);
    } else {
        nng_free(lenp, sizeof(uint32_t));
    }
}

// Test: Get and clean all messages
static void fuzz_test_get_and_clean_msgs(void) {
    uint32_t *lenp = nng_alloc(sizeof(uint32_t));
    if (!lenp) return;
    
    *lenp = 0;
    nng_msg **msgList = NULL;
    
    client_get_and_clean_msgs(g_sock, lenp, &msgList);
    
    if (*lenp > 0 && msgList) {
        free_msg_list(msgList, NULL, lenp, 1);
    } else {
        nng_free(lenp, sizeof(uint32_t));
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 16) return 0;
    if (size > 4096) size = 4096;
    
    // Setup on first run
    if (!initialized) {
        if (setup_exchange_server() != 0) {
            return 0;
        }
    }
    
    // Extract parameters from fuzzer input
    uint8_t mode = data[0];        // Test mode selector
    uint8_t qos = data[1] & 0x03;  // QoS: 0-3
    
    // Safely extract keys with bounds checking
    uint64_t key1 = 0;
    uint64_t key2 = 0;
    
    if (size >= 10) {
        memcpy(&key1, data + 2, sizeof(uint64_t));
    }
    
    if (size >= 18) {
        memcpy(&key2, data + 10, sizeof(uint64_t));
    }
    
    // Ensure key2 >= key1 for range queries
    if (key2 < key1) {
        uint64_t tmp = key1;
        key1 = key2;
        key2 = tmp;
    }
    
    // Calculate payload data and size
    const uint8_t *payload_data = NULL;
    size_t payload_size = 0;
    
    if (size > 18) {
        payload_data = data + 18;
        payload_size = size - 18;
    }
    
    // Mode-based testing
    if (mode & 0x01) {
        // Test: Publish single message
        if (payload_data && payload_size > 0) {
            fuzz_test_publish(payload_data, payload_size, key1, qos);
        }
    }
    
    if (mode & 0x02) {
        // Test: Publish multiple messages
        if (payload_data && payload_size > 0) {
            uint32_t num_msgs = (payload_size >= 10) ? 10 : payload_size;
            for (uint32_t i = 0; i < num_msgs && i * 10 < payload_size; i++) {
                uint64_t key = key1 + i;
                size_t chunk_size = (payload_size - i * 10 >= 10) ? 10 : (payload_size - i * 10);
                fuzz_test_publish(payload_data + (i * 10), chunk_size, key, qos);
            }
        }
    }
    
    if (mode & 0x04) {
        // Test: Get message by single key
        fuzz_test_get_msg_by_key(key1);
    }
    
    if (mode & 0x08) {
        // Test: Get messages by key with count
        uint32_t count = (data[1] >> 4) & 0x0F;  // 0-15
        if (count == 0) count = 1;
        fuzz_test_get_msgs_by_key(key1, count);
    }
    
    if (mode & 0x10) {
        // Test: Fuzzy search
        fuzz_test_get_msgs_fuzz(key1, key2);
    }
    
    if (mode & 0x20) {
        // Test: AIO-based retrieval (single key)
        fuzz_test_client_get_msgs(key1, 0);
    }
    
    if (mode & 0x40) {
        // Test: AIO-based retrieval (key range)
        fuzz_test_client_get_msgs(key1, key2);
    }
    
    if (mode & 0x80) {
        // Test: Get and clean all messages
        fuzz_test_get_and_clean_msgs();
    }
    
    return 0;
}

// Cleanup on exit
__attribute__((destructor))
static void cleanup_fuzzer(void) {
    if (initialized && g_conf) {
        // Note: Proper cleanup would require more work
        // but for fuzzing this is acceptable
    }
}