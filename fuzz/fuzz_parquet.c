/**
 * @file fuzz_parquet.c
 * @brief Complete parquet fuzzer - Fixed all warnings and double-free
 * 
 * KEY FIX: Use nng_alloc for packet data to match what parquet_data_free expects
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
#define FREE_STRUCT(p) free(p)

typedef struct {
    nng_aio *aio;
} work;

static bool initialized = false;
static char topic[] = "fuzz_topic";

// Track written files for read tests
#define MAX_FILENAMES 100
static char *written_filenames[MAX_FILENAMES];
static int num_written_files = 0;
static uint64_t min_written_key = UINT64_MAX;
static uint64_t max_written_key = 0;

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

// ✅ FIX: Allocate each packet->data separately using nng_alloc
// This way parquet_data_free can free them with nng_free
static parquet_data_packet ***parquet_data_packet_array_generate(
    uint32_t col_len, uint32_t row_len, bool generate_null, char **memory_out)
{
    parquet_data_packet ***packet_matrix =
        (parquet_data_packet ***)malloc(col_len * sizeof(parquet_data_packet **));
    if (!packet_matrix) return NULL;
    
    uint32_t c = 0;
    while (c < col_len) {
        packet_matrix[c] = (parquet_data_packet **)malloc(
            row_len * sizeof(parquet_data_packet *));
        if (!packet_matrix[c]) {
            for (uint32_t i = 0; i < c; i++) {
                free(packet_matrix[i]);
            }
            free(packet_matrix);
            return NULL;
        }
        
        uint32_t r = 0;
        while (r < row_len) {
            if (generate_null && (r * c % 3) == 1) {
                packet_matrix[c][r] = NULL;
            } else {
                packet_matrix[c][r] = (parquet_data_packet *)malloc(
                    sizeof(parquet_data_packet));
                if (!packet_matrix[c][r]) {
                    packet_matrix[c][r] = NULL;
                    r++;
                    continue;
                }
                
                // ✅ FIX: Use nng_alloc instead of malloc
                // parquet_data_free() calls nng_free on packet->data
                char temp_data[64] = {0};
                snprintf(temp_data, 64, "hello world_%u_%u", c, r);
                size_t data_len = strlen(temp_data);
                
                // Allocate with nng_alloc (will be freed by nng_free in parquet_data_free)
                packet_matrix[c][r]->data = (uint8_t *)nng_alloc(data_len + 1);
                if (!packet_matrix[c][r]->data) {
                    free(packet_matrix[c][r]);
                    packet_matrix[c][r] = NULL;
                    r++;
                    continue;
                }
                
                memcpy(packet_matrix[c][r]->data, temp_data, data_len);
                packet_matrix[c][r]->data[data_len] = '\0';
                packet_matrix[c][r]->size = data_len;
            }
            r++;
        }
        c++;
    }
    
    // ✅ No contiguous memory block - each packet has its own allocation
    *memory_out = NULL;
    
    return packet_matrix;
}

static uint64_t *keys_allocate(uint64_t *keys, uint32_t size) {
    uint32_t i = 0;
    uint64_t *keys_alloc = malloc(size * sizeof(uint64_t));
    if (!keys_alloc) return NULL;
    
    while (i < size) {
        keys_alloc[i] = keys[i];
        i++;
    }
    return keys_alloc;
}

// ✅ FIX: Callback doesn't need to free memory (NULL was passed)
static void fuzz_aio_cb(void *arg) {
    work *w = (work *)arg;
    nng_aio *aio = w->aio;
    
    // Track written files
    parquet_file_ranges *file_ranges = nng_aio_get_output(aio, 1);
    if (file_ranges && num_written_files < MAX_FILENAMES) {
        for (int i = 0; i < file_ranges->size && num_written_files < MAX_FILENAMES; i++) {
            parquet_file_range *range = file_ranges->range[i];
            if (range && range->filename) {
                written_filenames[num_written_files] = nng_strdup(range->filename);
                num_written_files++;
                
                if (range->start_idx < min_written_key) {
                    min_written_key = range->start_idx;
                }
                if (range->end_idx > max_written_key) {
                    max_written_key = range->end_idx;
                }
            }
        }
    }
    
    // No memory to free - we passed NULL to parquet_object_alloc
}

static int fuzz_write_data(uint32_t col_len, uint32_t row_len, 
                           uint64_t base_ts, bool generate_null) {
    uint64_t *keys_array = (uint64_t *)malloc(row_len * sizeof(uint64_t));
    if (!keys_array) return -1;
    
    for (uint32_t i = 0; i < row_len; i++) {
        keys_array[i] = base_ts + i;
    }
    
    uint64_t *ts = keys_allocate(keys_array, row_len);
    free(keys_array);
    if (!ts) return -1;
    
    char *memory = NULL;
    parquet_data_packet ***matrix = 
        parquet_data_packet_array_generate(col_len, row_len, generate_null, &memory);
    
    if (!matrix) {
        free(ts);
        return -1;
    }
    
    char **schema_l = malloc(sizeof(char *) * (col_len + 1));
    if (!schema_l) {
        free(ts);
        return -1;
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
        return -1;
    }
    
    work *w = ALLOC_STRUCT(w);
    if (!w) {
        parquet_data_free(pdata);
        return -1;
    }
    
    if (nng_aio_alloc(&w->aio, fuzz_aio_cb, w) != 0) {
        free(w);
        parquet_data_free(pdata);
        return -1;
    }
    
    // ✅ FIX: Pass NULL as memory (no contiguous block to manage)
    parquet_object *elem = parquet_object_alloc(pdata, WRITE_RAW, w->aio, NULL, topic);
    if (!elem) {
        nng_aio_free(w->aio);
        free(w);
        parquet_data_free(pdata);
        return -1;
    }
    
    parquet_write_batch_async(elem);
    nng_msleep(50);
    
    nng_aio_free(w->aio);
    free(w);
    
    return 0;
}

static void fuzz_test_parquet_find(uint64_t key) {
    char *value = (char *)parquet_find(topic, key);
    printf("fuzz_test_parquet_find: key = %lu, line: %d\n", key, __LINE__);
    if (value) {
        printf("fuzz_test_parquet_find: value = %s, line: %d\n", value, __LINE__);
        nng_strfree(value);
    } else {
        printf("fuzz_test_parquet_find: value = NULL, line: %d\n", __LINE__);   
    }
}

static void fuzz_test_parquet_find_span(uint64_t start_key, uint64_t end_key) {
    uint32_t size = 0;
    char **array = (char **)parquet_find_span(topic, start_key, end_key, &size);
    
    if (array) {
        for (uint32_t i = 0; i < size; i++) {
            if (array[i]) {
                nng_strfree(array[i]);
            }
        }
        nng_free(array, size);
    }
}

// ✅ FIX: Cast to non-const for API compatibility
static void fuzz_test_find_data_packet(char *filename, uint64_t key) {
    if (!filename) return;
    
    printf("fuzz_test_find_data_packet: filename = %s, key = %lu\n", filename, key);
    parquet_data_packet *pack = parquet_find_data_packet(NULL, filename, key);
    if (pack) {
        printf("fuzz_test_find_data_packet: pack = %p\n", pack);
        if (pack->data) {
            FREE_STRUCT(pack->data);
        }
        FREE_STRUCT(pack);
    }
}

static void fuzz_test_find_data_packets(char **filenames, uint64_t *keys, int count) {
    if (!filenames || !keys || count <= 0) return;
    
    printf("fuzz_test_find_data_packets: count = %d\n", count);
    for (int i = 0; i < count; i++) {
        printf("fuzz_test_find_data_packets: filename = %s, key = %lu\n", filenames[i], keys[i]);
    }
    parquet_data_packet **packs = parquet_find_data_packets(NULL, filenames, keys, count);
    if (packs) {
        printf("fuzz_test_find_data_packet: pack = %p\n", packs);
        for (int i = 0; i < count; i++) {
            if (packs[i]) {
                if (packs[i]->data) {
                    FREE_STRUCT(packs[i]->data);
                }
                FREE_STRUCT(packs[i]);
            }
        }
        free(packs);
    }
}

static void fuzz_test_get_data_packets_in_range(uint64_t start_key, uint64_t end_key) {
    parquet_filename_range range = {
        .keys = {start_key, end_key},
        .filename = NULL,
    };
    
    uint32_t size = 0;
    parquet_data_ret **rets = parquet_get_data_packets_in_range_by_column(
        &range, topic, NULL, 0, &size);
    
    if (rets) {
        for (uint32_t i = 0; i < size; i++) {
            parquet_data_ret *ret = rets[i];
            if (ret) {
                if (ret->schema) {
                    for (uint32_t c = 0; c < ret->col_len; c++) {
                        if (ret->schema[c]) {
                            FREE_STRUCT(ret->schema[c]);
                        }
                    }
                    FREE_STRUCT(ret->schema);
                }
                
                if (ret->payload_arr) {
                    for (uint32_t c = 0; c < ret->col_len; c++) {
                        if (ret->payload_arr[c]) {
                            for (uint32_t r = 0; r < ret->row_len; r++) {
                                parquet_data_packet *pack = ret->payload_arr[c][r];
                                if (pack) {
                                    if (pack->data) {
                                        FREE_STRUCT(pack->data);
                                    }
                                    FREE_STRUCT(pack);
                                }
                            }
                            FREE_STRUCT(ret->payload_arr[c]);
                        }
                    }
                    FREE_STRUCT(ret->payload_arr);
                }
                
                if (ret->ts) {
                    FREE_STRUCT(ret->ts);
                }
                
                FREE_STRUCT(ret);
            }
        }
        FREE_STRUCT(rets);
    }
}

static void fuzz_test_get_data_packets_by_column(uint64_t start_key, uint64_t end_key,
                                                  const char **schema, uint32_t schema_len) {
    parquet_filename_range range = {
        .keys = {start_key, end_key},
        .filename = NULL,
    };
    
    uint32_t size = 0;
    parquet_data_ret **rets = parquet_get_data_packets_in_range_by_column(
        &range, topic, schema, schema_len, &size);
    
    if (rets) {
        for (uint32_t i = 0; i < size; i++) {
            parquet_data_ret *ret = rets[i];
            if (ret) {
                if (ret->schema) {
                    for (uint32_t c = 0; c < ret->col_len; c++) {
                        if (ret->schema[c]) FREE_STRUCT(ret->schema[c]);
                    }
                    FREE_STRUCT(ret->schema);
                }
                if (ret->payload_arr) {
                    for (uint32_t c = 0; c < ret->col_len; c++) {
                        if (ret->payload_arr[c]) {
                            for (uint32_t r = 0; r < ret->row_len; r++) {
                                if (ret->payload_arr[c][r]) {
                                    if (ret->payload_arr[c][r]->data) {
                                        FREE_STRUCT(ret->payload_arr[c][r]->data);
                                    }
                                    FREE_STRUCT(ret->payload_arr[c][r]);
                                }
                            }
                            FREE_STRUCT(ret->payload_arr[c]);
                        }
                    }
                    FREE_STRUCT(ret->payload_arr);
                }
                if (ret->ts) FREE_STRUCT(ret->ts);
                FREE_STRUCT(ret);
            }
        }
        FREE_STRUCT(rets);
    }
}

static void fuzz_test_get_file_ranges(uint64_t start_key, uint64_t end_key) {
    parquet_filename_range **file_ranges = parquet_get_file_ranges(start_key, end_key, topic);
    
    if (file_ranges) {
        parquet_filename_range **p = file_ranges;
        while (*p) {
            if ((*p)->filename) {
                nng_strfree((char *)(*p)->filename);
            }
            FREE_STRUCT(*p);
            p++;
        }
        FREE_STRUCT(file_ranges);
    }
}

// ✅ FIX: Use correct types for parquet_get_key_span
static void fuzz_test_get_key_span(void) {
    const char *topics[] = {topic};  // ✅ const char**
    uint64_t *data_span = NULL;      // ✅ Will be allocated by function
    uint64_t *sums = NULL;           // ✅ Will be allocated by function
    
    // ✅ FIX: Pass addresses of pointers
    bool result = parquet_get_key_span(topics, 1, &data_span, &sums);
    if (result && data_span && sums) {
        parquet_free_key_span(data_span, sums, 1);
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 16) return 0;
    if (size > 4096) size = 4096;
    
    if (!initialized) {
        if (setup_parquet() != 0) {
            return 0;
        }
    }
    
    uint8_t mode = data[0];
    uint8_t control = data[1];
    uint32_t col_len = ((control & 0x0F) % 5) + 1;
    uint32_t row_len = (((control >> 4) & 0x0F) % 10) + 1;
    bool generate_null = (data[2] & 0x1);
    
    uint64_t base_ts = 1000;
    if (size >= 11) {
        memcpy(&base_ts, data + 3, sizeof(uint64_t));
    }
    
    // if (mode & 0x01) {
        fuzz_write_data(col_len, row_len, base_ts, generate_null);
        // Wait longer for writes to complete and files to be created
        nng_msleep(150);
    // }
    
    // Only test reads if we successfully wrote some data
    // Check both num_written_files and that we have valid key range
    if (num_written_files > 0 && max_written_key >= min_written_key) {
        uint64_t search_key = base_ts + (row_len / 2);
        
        if (mode & 0x02) {
            fuzz_test_parquet_find(search_key);
        }
        
        if (mode & 0x04) {
            fuzz_test_parquet_find_span(min_written_key, max_written_key);
        }
        
        if (mode & 0x08) {
            // Double check we have valid filename
            if (written_filenames[0] != NULL) {
                fuzz_test_find_data_packet(written_filenames[0], search_key);
            }
        }
        
        if (mode & 0x10) {
            // Validate filenames before using them
            bool has_valid_files = false;
            for (int i = 0; i < num_written_files && i < 3; i++) {
                if (written_filenames[i] != NULL) {
                    has_valid_files = true;
                    break;
                }
            }
            
            if (has_valid_files) {
                uint64_t keys[] = {base_ts, base_ts + 1, base_ts + 2};
                int key_count = (num_written_files < 3) ? num_written_files : 3;
                fuzz_test_find_data_packets(written_filenames, keys, key_count);
            }
        }
        
        if (mode & 0x20) {
            fuzz_test_get_data_packets_in_range(min_written_key, max_written_key);
        }
        
        if (mode & 0x40) {
            const char *schema[] = {"data0", "data1"};
            uint32_t schema_len = (col_len < 2) ? col_len : 2;
            fuzz_test_get_data_packets_by_column(min_written_key, max_written_key, 
                                                 schema, schema_len);
        }
        
        if (mode & 0x80) {
            fuzz_test_get_file_ranges(min_written_key, max_written_key);
        }
        
        if ((mode & 0x0F) == 0x0F) {
            fuzz_test_get_key_span();
        }
    }
    
    return 0;
}

__attribute__((destructor))
static void cleanup_fuzzer(void) {
    for (int i = 0; i < num_written_files; i++) {
        if (written_filenames[i]) {
            nng_strfree(written_filenames[i]);
        }
    }
}