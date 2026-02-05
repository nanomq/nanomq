/**
 * @file fuzz_parquet.c
 * @brief Parquet fuzzer - fixed double-free issue
 * 
 * KEY FIX: Don't free memory in callback - let parquet system handle it
 * OR: Pass NULL as memory to parquet_object_alloc
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "nng/nng.h"
#include "nng/supplemental/nanolib/conf.h"
#include "nng/supplemental/nanolib/parquet.h"

#define ALLOC_STRUCT(v) (v = calloc(1, sizeof(*v)))

typedef struct {
    nng_aio *aio;
} work;

static bool initialized = false;
static char topic[] = "fuzz_topic";

static void clear_folder(const char *folderPath) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf %s/* 2>/dev/null", folderPath);
    system(cmd);
}

static conf_parquet *conf_parquet_init(void) {
    conf_parquet *conf;
    ALLOC_STRUCT(conf);
    if (!conf) return NULL;
    
    conf->enable = true;
    conf->dir = strdup("/tmp/fuzz_parquet");
    conf->file_name_prefix = strdup("fuzz");
    conf->comp_type = UNCOMPRESSED;
    conf->file_count = 5;
    conf->file_index = 0;
    conf->file_size = 4000;
    conf->encryption.enable = false;
    conf->encryption.key = "0123456789012345";
    conf->encryption.key_id = "kf";
    conf->encryption.type = AES_GCM_V1;
    
    mkdir(conf->dir, 0777);
    clear_folder(conf->dir);
    
    return conf;
}

static void conf_exchange_init(conf_exchange *conf, size_t node_count) {
    if (!conf) return;
    
    conf->count = node_count;
    conf->nodes = (conf_exchange_node **)calloc(
        node_count, sizeof(conf_exchange_node *));
    conf->encryption = (conf_exchange_encryption *)calloc(
        1, sizeof(conf_exchange_encryption));
    conf->default_parquet = (conf_parquet *)calloc(1, sizeof(conf_parquet));
    
    conf->encryption->enable = false;
    conf->encryption->key = NULL;
    
    conf->default_parquet->enable = false;
    conf->default_parquet->name = strdup("default_parquet");
    conf->default_parquet->dir = strdup("/var/log/parquet");
    conf->default_parquet->file_name_prefix = strdup("log");
    conf->default_parquet->file_count = 10;
    conf->default_parquet->limit_frequency = 1000;
    conf->default_parquet->file_index = 0;
    conf->default_parquet->file_size = 10 * 1024 * 1024;
    conf->default_parquet->comp_type = UNCOMPRESSED;
    conf->default_parquet->encryption.enable = false;
    conf->default_parquet->encryption.key_id = NULL;
    conf->default_parquet->encryption.key = NULL;
    conf->default_parquet->encryption.type = AES_GCM_V1;
    
    for (size_t i = 0; i < node_count; i++) {
        conf->nodes[i] = (conf_exchange_node *)calloc(
            1, sizeof(conf_exchange_node));
        
        conf->nodes[i]->name = strdup(topic);
        conf->nodes[i]->topic = strdup(topic);
        conf->nodes[i]->rbufs = NULL;
        conf->nodes[i]->rbufs_sz = 0;
        conf->nodes[i]->streamType = 0;
        conf->nodes[i]->chunk_size = 1024;
        conf->nodes[i]->limit_frequency = 1000;
        conf->nodes[i]->parquet = conf_parquet_init();
        conf->nodes[i]->sock = NULL;
        conf->nodes[i]->mtx = NULL;
        conf->nodes[i]->exchange_url = NULL;
    }
}

static int setup_parquet(void) {
    if (initialized) return 0;
    
    conf_exchange *conf;
    ALLOC_STRUCT(conf);
    if (!conf) return -1;
    
    conf_exchange_init(conf, 1);
    parquet_write_launcher(conf);
    
    initialized = true;
    return 0;
}

// ✅ FIX: Allocate each data buffer separately (not from contiguous block)
// This way parquet_data_free() can safely free each one
static parquet_data_packet ***parquet_data_packet_array_generate(
    uint32_t col_len, uint32_t row_len, bool generate_null, char **memory_out)
{
    parquet_data_packet ***packet_matrix =
        (parquet_data_packet ***)malloc(col_len * sizeof(parquet_data_packet **));
    if (!packet_matrix) return NULL;
    
    for (uint32_t c = 0; c < col_len; c++) {
        packet_matrix[c] = (parquet_data_packet **)malloc(
            row_len * sizeof(parquet_data_packet *));
        if (!packet_matrix[c]) {
            // Cleanup on error
            for (uint32_t i = 0; i < c; i++) {
                free(packet_matrix[i]);
            }
            free(packet_matrix);
            return NULL;
        }
        
        for (uint32_t r = 0; r < row_len; r++) {
            if (generate_null && (r * c % 3) == 1) {
                packet_matrix[c][r] = NULL;
            } else {
                packet_matrix[c][r] = (parquet_data_packet *)malloc(
                    sizeof(parquet_data_packet));
                if (!packet_matrix[c][r]) {
                    packet_matrix[c][r] = NULL;
                    continue;
                }
                
                // ✅ FIX: Allocate SEPARATE buffer for each data
                // (not from contiguous block)
                char *data_buf = (char *)malloc(64);
                if (!data_buf) {
                    free(packet_matrix[c][r]);
                    packet_matrix[c][r] = NULL;
                    continue;
                }
                
                snprintf(data_buf, 64, "hello world_%u_%u", c, r);
                packet_matrix[c][r]->size = strlen(data_buf);
                packet_matrix[c][r]->data = data_buf;  // ← Separate allocation
            }
        }
    }
    
    // ✅ FIX: No contiguous memory block needed
    *memory_out = NULL;
    
    return packet_matrix;
}

static uint64_t *keys_allocate(uint64_t *keys, uint32_t size) {
    uint64_t *keys_alloc = malloc(size * sizeof(uint64_t));
    if (!keys_alloc) return NULL;
    
    for (uint32_t i = 0; i < size; i++) {
        keys_alloc[i] = keys[i];
    }
    return keys_alloc;
}

// ✅ FIX: Callback doesn't need to free anything
// parquet system will free everything via parquet_data_free()
static void fuzz_aio_cb(void *arg) {
    // Just a placeholder - parquet system handles cleanup
    (void)arg;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 16) return 0;
    if (size > 4096) size = 4096;
    
    if (!initialized) {
        if (setup_parquet() != 0) {
            return 0;
        }
    }
    
    uint8_t control = data[0];
    uint32_t col_len = (control & 0x0F) % 5 + 1;
    uint32_t row_len = ((control >> 4) & 0x0F) % 10 + 1;
    bool generate_null = (data[1] & 0x1);
    
    uint64_t base_ts = 1000;
    if (size >= 10) {
        memcpy(&base_ts, data + 2, sizeof(uint64_t));
    }
    
    uint64_t *keys_array = (uint64_t *)malloc(row_len * sizeof(uint64_t));
    if (!keys_array) return 0;
    
    for (uint32_t i = 0; i < row_len; i++) {
        keys_array[i] = base_ts + i;
    }
    
    uint64_t *ts = keys_allocate(keys_array, row_len);
    free(keys_array);
    if (!ts) return 0;
    
    char *memory = NULL;  // Will be NULL
    parquet_data_packet ***matrix = 
        parquet_data_packet_array_generate(col_len, row_len, generate_null, &memory);
    
    if (!matrix) {
        free(ts);
        return 0;
    }
    
    char **schema_l = malloc(sizeof(char *) * (col_len + 1));
    if (!schema_l) {
        free(ts);
        // Need to cleanup matrix manually
        return 0;
    }
    
    schema_l[0] = strdup("ts");
    for (uint32_t i = 0; i < col_len; i++) {
        char name[32];
        snprintf(name, sizeof(name), "data%u", i);
        schema_l[i + 1] = strdup(name);
    }
    
    parquet_data *pdata = parquet_data_alloc(schema_l, matrix, ts, col_len, row_len);
    if (!pdata) {
        for (uint32_t i = 0; i <= col_len; i++) {
            free(schema_l[i]);
        }
        free(schema_l);
        free(ts);
        // Cleanup matrix
        return 0;
    }
    
    work *w = ALLOC_STRUCT(w);
    if (!w) {
        parquet_data_free(pdata);
        return 0;
    }
    
    if (nng_aio_alloc(&w->aio, fuzz_aio_cb, w) != 0) {
        free(w);
        parquet_data_free(pdata);
        return 0;
    }
    
    // ✅ FIX: Pass NULL as memory (no contiguous block to free)
    parquet_object *elem = parquet_object_alloc(pdata, WRITE_RAW, w->aio, NULL, topic);
    if (!elem) {
        nng_aio_free(w->aio);
        free(w);
        parquet_data_free(pdata);
        return 0;
    }
    
    parquet_write_batch_async(elem);
    
    // Wait for completion
    nng_msleep(50);
    
    // Cleanup
    nng_aio_free(w->aio);
    free(w);
    
    return 0;
}