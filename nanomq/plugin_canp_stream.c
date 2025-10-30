//
// Copyright 2025 NanoMQ Team
//
// CANP stream plugin
// |ts(8B)|len(4B)| [ tsdiff(1B)|busid(1B)|canid(2B)|len(2B)|payload(len B) ] ...
//
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <sys/stat.h>
#include "include/plugin.h"
#include "nng/exchange/stream/stream.h"

#ifdef SUPP_PARQUET
#include "nng/supplemental/nanolib/parquet.h"
#endif

#define CANP_STREAM_NAME "canp"
#define CANP_STREAM_ID   0x2

static inline void be_memcpy(void *dst, const void *src, uint32_t len)
{
    for (uint32_t i = 0; i < len; i++) {
        ((uint8_t *)dst)[i] = ((const uint8_t *)src)[len - i - 1];
    }
}

static inline uint32_t be32toh_u32(const void *src)
{
    uint32_t v = 0;
    for (uint32_t i = 0; i < 4; i++) {
        ((uint8_t *)&v)[i] = ((const uint8_t *)src)[3 - i];
    }
    return v;
}

static inline uint16_t be16toh_u16(const void *src)
{
    uint16_t v = 0;
    for (uint32_t i = 0; i < 2; i++) {
        ((uint8_t *)&v)[i] = ((const uint8_t *)src)[1 - i];
    }
    return v;
}

static inline void htobe64_mem(void *dst, const void *src)
{
    for (uint32_t i = 0; i < 8; i++) {
        ((uint8_t *)dst)[i] = ((const uint8_t *)src)[7 - i];
    }
}

static inline void htobe32_mem(void *dst, const void *src)
{
    for (uint32_t i = 0; i < 4; i++) {
        ((uint8_t *)dst)[i] = ((const uint8_t *)src)[3 - i];
    }
}

static inline void htobe16_mem(void *dst, const void *src)
{
    for (uint32_t i = 0; i < 2; i++) {
        ((uint8_t *)dst)[i] = ((const uint8_t *)src)[1 - i];
    }
}

static char *u16_to_hex4(uint16_t v)
{
    char *buf = nng_alloc(5);
    if (!buf) return NULL;
    snprintf(buf, 5, "%04x", v);
    return buf;
}

static char *busid_canid_to_hex6(uint8_t busid, uint16_t canid)
{
    char *buf = nng_alloc(7);
    if (!buf) return NULL;
    snprintf(buf, 7, "%02x%04x", busid, canid);
    return buf;
}

static void schema_free(char **schema, uint32_t len)
{
    if (schema == NULL) return;
    for (uint32_t i = 0; i < len; i++) {
        if (schema[i] != NULL) {
            nng_free(schema[i], strlen(schema[i]) + 1);
        }
    }
    nng_free(schema, len * sizeof(char *));
}

struct schema_array {
    char **schema;
    nng_id_map *index_map;
    uint32_t len;
};

static void schema_array_cb(void *id, void *data, void *arg)
{
    struct schema_array *arr = (struct schema_array *)arg;
    if (!arr) return;
    nng_id_set(arr->index_map, (*(uint32_t *)id), (void *)(uintptr_t)arr->len);
    arr->schema[arr->len++] = data;
}

static void collect_schema_from_row(uint8_t *p, uint32_t remain, nng_id_map *schema_map, uint32_t *pcount)
{
    while (remain >= 6) {
        uint8_t tsdiff = p[0];
        (void)tsdiff;
        uint8_t busid = p[1];
        (void)busid;
        uint16_t canid = be16toh_u16(p + 2);
        uint16_t plen = be16toh_u16(p + 4);
        if ((uint32_t)(6 + plen) > remain) {
            break;
        }
        // 使用 canid 作为 schema 维度（4 位十六进制）
        void *old = nng_id_get(schema_map, (uint32_t)canid);
        if (old == NULL) {
            char *hex = u16_to_hex4(canid);
            if (hex) {
                nng_id_set(schema_map, (uint32_t)canid, hex);
                *pcount += 1;
            }
        }
        p += 6 + plen;
        remain -= 6 + plen;
    }
}

static char **canp_get_schemas(void **datas,
                               uint32_t *lens,
                               uint32_t cnt,
                               uint32_t *pcol_len,
                               nng_id_map *index_map)
{
    int ret = 0;
    uint32_t schema_map_len = 0;
    nng_id_map *schema_map = NULL;
    // canid 范围 0..0xFFFF
    ret = nng_id_map_alloc(&schema_map, 0, 0xFFFF, false);
    if (ret != 0) return NULL;

    for (uint32_t i = 0; i < cnt; i++) {
        if (lens[i] < 12) continue;
        uint8_t *p = (uint8_t *)datas[i];
        uint32_t remain = lens[i];
        while (remain >= 12) {
            uint64_t ts = 0;
            be_memcpy(&ts, p, 8);
            (void)ts;
            uint32_t row_len = be32toh_u32(p + 8);
            if (row_len > remain - 12) {
                break;
            }
            uint8_t *row = p + 12;
            collect_schema_from_row(row, row_len, schema_map, &schema_map_len);
            p += 12 + row_len;
            remain -= 12 + row_len;
        }
    }

    if (schema_map_len == 0) {
        nng_id_map_free(schema_map);
        return NULL;
    }

    char **schemas = nng_alloc((schema_map_len + 1) * sizeof(char *));
    if (!schemas) {
        nng_id_map_free(schema_map);
        return NULL;
    }
    schemas[0] = nng_alloc(strlen("ts") + 1);
    strcpy(schemas[0], "ts");

    struct schema_array arr;
    arr.schema = schemas;
    arr.len = 1;
    arr.index_map = index_map;
    nng_id_map_foreach2(schema_map, schema_array_cb, &arr);
    nng_id_map_free(schema_map);
    *pcol_len = schema_map_len;
    return schemas;
}

static inline void payload_arr_free(parquet_data_packet ***payload_arr, uint32_t row_len, uint32_t col_len)
{
    if (!payload_arr) return;
    for (uint32_t i = 0; i < col_len; i++) {
        if (payload_arr[i]) {
            for (uint32_t j = 0; j < row_len; j++) {
                if (payload_arr[i][j]) {
                    if (payload_arr[i][j]->data && payload_arr[i][j]->size > 0) {
                        nng_free(payload_arr[i][j]->data, payload_arr[i][j]->size);
                    }
                    nng_free(payload_arr[i][j], sizeof(parquet_data_packet));
                }
            }
            nng_free(payload_arr[i], sizeof(parquet_data_packet *) * row_len);
        }
    }
    nng_free(payload_arr, sizeof(parquet_data_packet **) * col_len * row_len);
}

// ===== v2 packing: pack multiple segments into consolidated cell =====
// v1 segment layout (repeated): |tsdiff(1)|busid(1)|len(2)|payload(len)|
// v2 cell layout: |seg_count(1)|flags(1)|busid(single or array)|tsdiff_array(seg_count)|payloads(seg_count*L)|
// flags bit0: 0 = single busid follows; 1 = busid array of seg_count bytes
static int canp_cell_pack_v2(parquet_data_packet **pcell)
{
    if (!pcell || !*pcell) return 0;
    parquet_data_packet *cell = *pcell;
    if (!cell->data || cell->size < 4) return 0;
    uint8_t *d = cell->data;
    uint32_t n = cell->size;

    // Count segments and determine fixed payload length L
    uint32_t pos = 0;
    uint32_t segs = 0;
    int fixed_len = -1;
    while (n - pos >= 4) {
        uint16_t plen = (uint16_t)((d[pos + 2] << 8) | d[pos + 3]);
        if (n - pos < (uint32_t)(4 + plen)) break;
        if (fixed_len < 0) fixed_len = (int)plen;
        else if (fixed_len != (int)plen) {
            // not fixed length, skip packing
            return 0;
        }
        segs++;
        pos += (uint32_t)(4 + plen);
        if (segs > 255) return 0; // v2 header seg_count is u8
    }
    if (segs == 0) return 0;
    if ((uint32_t)fixed_len * segs + 4 > 0x7FFFFFFF) return 0; // basic guard

    // Check busid variance
    pos = 0;
    int all_same_busid = 1;
    uint8_t first_busid = d[1];
    for (uint32_t i = 0; i < segs; i++) {
        uint8_t bus = d[pos + 1];
        uint16_t plen = (uint16_t)((d[pos + 2] << 8) | d[pos + 3]);
        if (bus != first_busid) { all_same_busid = 0; break; }
        pos += (uint32_t)(4 + plen);
    }

    uint8_t flags = (all_same_busid ? 0x00 : 0x01);
    // bit1 indicates plane-mask present
    flags |= 0x02;
    uint32_t L = (uint32_t)fixed_len;

    // Build plane mask: 1 means plane is constant across segs
    uint32_t rpos = 0;
    uint8_t *const_vals = nng_alloc(L);
    if (!const_vals) return 0;
    uint8_t *mask = nng_alloc((L + 7) / 8);
    if (!mask) { nng_free(const_vals, L); return 0; }
    for (uint32_t i = 0; i < (L + 7) / 8; i++) mask[i] = 0;
    for (uint32_t b = 0; b < L; b++) {
        int is_const = 1;
        // first segment's value at byte b
        uint8_t first_val = d[rpos + 4 + b];
        uint32_t check_pos = 0;
        for (uint32_t s = 0; s < segs; s++) {
            uint32_t seg_off = check_pos;
            uint8_t v = d[seg_off + 4 + b];
            if (v != first_val) { is_const = 0; break; }
            uint16_t plen = (uint16_t)((d[seg_off + 2] << 8) | d[seg_off + 3]);
            check_pos += (uint32_t)(4 + plen);
        }
        const_vals[b] = first_val;
        if (is_const) {
            mask[b / 8] |= (uint8_t)(1u << (7 - (b % 8)));
        }
    }

    uint32_t busid_bytes = all_same_busid ? 1u : segs;
    uint32_t mask_bytes = (L + 7) / 8;
    // size: seg_count(1)+flags(1)+busid+tsdiff(segs)+L(1)+mask(mask_bytes)+const_vals(count1)+var_planes(count0*segs)
    uint32_t const_count = 0;
    for (uint32_t b = 0; b < L; b++) if (mask[b / 8] & (uint8_t)(1u << (7 - (b % 8)))) const_count++;
    uint32_t var_count = L - const_count;
    uint32_t new_size = 1u + 1u + busid_bytes + segs + 1u + mask_bytes + const_count * 1u + var_count * segs;
    uint8_t *buf = nng_alloc(new_size);
    if (!buf) { nng_free(const_vals, L); nng_free(mask, mask_bytes); return 0; }

    // Fill v2.1
    uint32_t w = 0;
    buf[w++] = (uint8_t)segs; // seg_count
    buf[w++] = flags;         // flags (bit1 set)
    // busid
    if (all_same_busid) {
        buf[w++] = first_busid;
    } else {
        pos = 0;
        for (uint32_t i = 0; i < segs; i++) {
            buf[w++] = d[pos + 1];
            uint16_t plen = (uint16_t)((d[pos + 2] << 8) | d[pos + 3]);
            pos += (uint32_t)(4 + plen);
        }
    }
    // tsdiff array
    pos = 0;
    for (uint32_t i = 0; i < segs; i++) {
        buf[w++] = d[pos + 0];
        uint16_t plen = (uint16_t)((d[pos + 2] << 8) | d[pos + 3]);
        pos += (uint32_t)(4 + plen);
    }
    // payloads with plane mask
    buf[w++] = (uint8_t)L; // store L explicitly for robust parsing
    // mask
    for (uint32_t i = 0; i < mask_bytes; i++) buf[w++] = mask[i];
    // write constant planes' values in order
    for (uint32_t b = 0; b < L; b++) {
        if (mask[b / 8] & (uint8_t)(1u << (7 - (b % 8)))) {
            buf[w++] = const_vals[b];
        }
    }
    // write variable planes in order, each plane seg_count bytes (plane-major)
    // rebuild plane data from original segments
    // We already validated equal lengths; extract per plane
    // Create an array of pointers for segment payload start
    uint32_t *seg_offsets = nng_alloc(sizeof(uint32_t) * segs);
    if (!seg_offsets) { nng_free(const_vals, L); nng_free(mask, mask_bytes); nng_free(buf, new_size); return 0; }
    pos = 0;
    for (uint32_t i = 0; i < segs; i++) {
        seg_offsets[i] = pos + 4;
        pos += (uint32_t)(4 + L);
    }
    for (uint32_t b = 0; b < L; b++) {
        if ((mask[b / 8] & (uint8_t)(1u << (7 - (b % 8))))) continue; // constant plane skipped
        for (uint32_t i = 0; i < segs; i++) {
            buf[w++] = d[seg_offsets[i] + b];
        }
    }

    // cleanup temp
    nng_free(seg_offsets, sizeof(uint32_t) * segs);
    nng_free(const_vals, L);
    nng_free(mask, mask_bytes);

    // Replace cell
    nng_free(cell->data, cell->size);
    cell->data = buf;
    cell->size = new_size;
    return 1;
}

static void canp_apply_pack_v2(parquet_data_packet ***payload_arr, uint32_t row_len, uint32_t col_len)
{
    if (!payload_arr) return;
    for (uint32_t c = 0; c < col_len; c++) {
        for (uint32_t r = 0; r < row_len; r++) {
            if (payload_arr[c][r]) {
                canp_cell_pack_v2(&payload_arr[c][r]);
            }
        }
//		nng_msleep(10);
    }
}

static void canpStream_free(struct stream_data_out *out)
{
    if (!out) return;
    schema_free(out->schema, out->col_len + 1);
    payload_arr_free(out->payload_arr, out->row_len, out->col_len);
    nng_free(out->ts, sizeof(uint64_t) * out->row_len);
    nng_free(out, sizeof(struct stream_data_out));
}

static int canp_msg_parse(parquet_data_packet ***data,
                          void *buf,
                          uint32_t len,
                          nng_id_map *index_map,
                          uint32_t row_index)
{
    if (len < 12) return 0;
    uint8_t *p = (uint8_t *)buf;
    uint32_t remain = len;
    while (remain >= 12) {
        uint64_t ts = 0;
        be_memcpy(&ts, p, 8);
        (void)ts;
        uint32_t row_len = be32toh_u32(p + 8);
        if (row_len > remain - 12) {
            break;
        }
        uint8_t *row = p + 12;
        uint32_t r = row_len;
        while (r >= 6) {
            uint8_t tsdiff = row[0];
            uint8_t busid = row[1];
            uint16_t canid = be16toh_u16(row + 2);
            uint16_t plen  = be16toh_u16(row + 4);
            if ((uint32_t)(6 + plen) > r) {
                break;
            }
            // 以 canid 作为列索引
            uint32_t offset = (uint32_t)(uintptr_t)nng_id_get(index_map, (uint32_t)canid);
            if (offset != 0) {
                offset -= 1;
                // 单元格内累积多个段：每段格式 tsdiff(1)|busid(1)|len(2)|payload
                uint32_t seg_size = (uint32_t)(1 + 1 + 2 + plen);
                if (data[offset][row_index] == NULL) {
                    data[offset][row_index] = nng_alloc(sizeof(parquet_data_packet));
                    if (!data[offset][row_index]) return -1;
                    uint8_t *cell_buf = nng_alloc(seg_size);
                    if (!cell_buf) {
                        nng_free(data[offset][row_index], sizeof(parquet_data_packet));
                        data[offset][row_index] = NULL;
                        return -1;
                    }
                    cell_buf[0] = tsdiff;
                    cell_buf[1] = busid;
                    cell_buf[2] = row[4];
                    cell_buf[3] = row[5];
                    memcpy(cell_buf + 4, row + 6, plen);
                    data[offset][row_index]->size = seg_size;
                    data[offset][row_index]->data = cell_buf;
                } else {
                    parquet_data_packet *pkt = data[offset][row_index];
                    uint8_t *new_buf = nng_alloc(pkt->size + seg_size);
                    if (!new_buf) return -1;
                    memcpy(new_buf, pkt->data, pkt->size);
                    uint32_t pos = pkt->size;
                    new_buf[pos++] = tsdiff;
                    new_buf[pos++] = busid;
                    new_buf[pos++] = row[4];
                    new_buf[pos++] = row[5];
                    memcpy(new_buf + pos, row + 6, plen);
                    if (pkt->data && pkt->size > 0) {
                        nng_free(pkt->data, pkt->size);
                    }
                    pkt->data = new_buf;
                    pkt->size += seg_size;
                }
            }
            row += 6 + plen;
            r   -= 6 + plen;
        }
        p += 12 + row_len;
        remain -= 12 + row_len;
    }
    return 0;
}

// Count inner rows inside one input buffer: number of |ts(8)|len(4)|row| blocks
static uint32_t canp_count_inner_rows(void *buf, uint32_t len)
{
    if (buf == NULL || len < 12) return 0;
    uint8_t *p = (uint8_t *)buf;
    uint32_t remain = len;
    uint32_t cnt = 0;
    while (remain >= 12) {
        uint32_t row_len = be32toh_u32(p + 8);
        if (row_len > remain - 12) break;
        cnt++;
        p += 12 + row_len;
        remain -= 12 + row_len;
    }
    return cnt;
}

// Place all inner rows from one input buffer into output rows starting at base_row_index
static int canp_place_inner_rows(parquet_data_packet ***data,
                                 void *buf,
                                 uint32_t len,
                                 nng_id_map *index_map,
                                 uint32_t base_row_index,
                                 uint64_t *ts_out)
{
    if (buf == NULL || len < 12) return 0;
    uint8_t *p = (uint8_t *)buf;
    uint32_t remain = len;
    uint32_t current = 0;
    while (remain >= 12) {
        uint64_t ts = 0;
        be_memcpy(&ts, p, 8);
        uint32_t row_len = be32toh_u32(p + 8);
        if (row_len > remain - 12) break;
        uint8_t *row = p + 12;
        uint32_t r = row_len;
        uint32_t row_index = base_row_index + current;
        if (ts_out) ts_out[row_index] = ts;
        while (r >= 6) {
            uint8_t tsdiff = row[0];
            uint8_t busid  = row[1];
            uint16_t canid = be16toh_u16(row + 2);
            uint16_t plen  = be16toh_u16(row + 4);
            if ((uint32_t)(6 + plen) > r) break;
            uint32_t offset = (uint32_t)(uintptr_t)nng_id_get(index_map, (uint32_t)canid);
            if (offset != 0) {
                offset -= 1;
                uint32_t seg_size = (uint32_t)(1 + 1 + 2 + plen);
                if (data[offset][row_index] == NULL) {
                    data[offset][row_index] = nng_alloc(sizeof(parquet_data_packet));
                    if (!data[offset][row_index]) return -1;
                    uint8_t *cell_buf = nng_alloc(seg_size);
                    if (!cell_buf) {
                        nng_free(data[offset][row_index], sizeof(parquet_data_packet));
                        data[offset][row_index] = NULL;
                        return -1;
                    }
                    cell_buf[0] = tsdiff;
                    cell_buf[1] = busid;
                    cell_buf[2] = row[4];
                    cell_buf[3] = row[5];
                    memcpy(cell_buf + 4, row + 6, plen);
                    data[offset][row_index]->size = seg_size;
                    data[offset][row_index]->data = cell_buf;
                } else {
                    parquet_data_packet *pkt = data[offset][row_index];
                    uint8_t *new_buf = nng_alloc(pkt->size + seg_size);
                    if (!new_buf) return -1;
                    memcpy(new_buf, pkt->data, pkt->size);
                    uint32_t pos2 = pkt->size;
                    new_buf[pos2++] = tsdiff;
                    new_buf[pos2++] = busid;
                    new_buf[pos2++] = row[4];
                    new_buf[pos2++] = row[5];
                    memcpy(new_buf + pos2, row + 6, plen);
                    if (pkt->data && pkt->size > 0) {
                        nng_free(pkt->data, pkt->size);
                    }
                    pkt->data = new_buf;
                    pkt->size += seg_size;
                }
            }
            row += 6 + plen;
            r   -= 6 + plen;
        }
        p += 12 + row_len;
        remain -= 12 + row_len;
        current++;
    }
    return 0;
}

static struct stream_data_out *canpStream_init(void *data)
{
    int ret = 0;
    struct stream_data_in *in = (struct stream_data_in *)data;
    if (in == NULL || in->len == 0) {
        log_error("input_stream is NULL");
        return NULL;
    }
    struct stream_data_out *out = nng_alloc(sizeof(struct stream_data_out));
    if (!out) {
        log_error("out is NULL");
        return NULL;
    }
    out->schema = NULL;
    out->payload_arr = NULL;
    out->ts = NULL;
    out->row_len = in->len;

    nng_id_map *index_map = NULL;
    nng_id_map_alloc(&index_map, 0, 0xFFFFFF, false);
    if (index_map == NULL) {
        canpStream_free(out);
        log_error("index_map is NULL");
        return NULL;
    }

    out->schema = canp_get_schemas(in->datas, in->lens, in->len, &out->col_len, index_map);
    if (!out->schema) {
        canpStream_free(out);
        nng_id_map_free(index_map);
        log_error("out->schema is NULL");
        return NULL;
    }

    // Re-calc row_len as total inner rows and allocate ts accordingly
    uint32_t total_rows = 0;
    for (uint32_t i = 0; i < in->len; i++) {
        total_rows += canp_count_inner_rows(in->datas[i], in->lens[i]);
    }
    out->row_len = total_rows;
    out->ts = nng_alloc(sizeof(uint64_t) * out->row_len);
    if (!out->ts) {
        canpStream_free(out);
        nng_id_map_free(index_map);
        log_error("out->ts is NULL");
        return NULL;
    }

    out->payload_arr = nng_alloc(sizeof(parquet_data_packet **) * out->col_len);
    if (!out->payload_arr) {
        canpStream_free(out);
        nng_id_map_free(index_map);
        log_error("out->payload_arr is NULL");
        return NULL;
    }
    for (uint32_t c = 0; c < out->col_len; c++) {
        out->payload_arr[c] = nng_alloc(sizeof(parquet_data_packet *) * out->row_len);
        if (!out->payload_arr[c]) {
            canpStream_free(out);
            nng_id_map_free(index_map);
            log_error("out->payload_arr[c] is NULL");
            return NULL;
        }
        for (uint32_t r = 0; r < out->row_len; r++) {
            out->payload_arr[c][r] = NULL;
        }
    }

    // Place all inner rows sequentially into output rows and fill ts
    uint32_t base = 0;
    for (uint32_t i = 0; i < in->len; i++) {
        uint32_t inner = canp_count_inner_rows(in->datas[i], in->lens[i]);
        if (inner == 0) continue;
        ret = canp_place_inner_rows(out->payload_arr, in->datas[i], in->lens[i], index_map, base, out->ts);
        if (ret != 0) {
            canpStream_free(out);
            nng_id_map_free(index_map);
            log_error("canp_place_inner_rows failed");
            return NULL;
        }
        base += inner;
//		nng_msleep(10);
    }

    // Apply v2 packing to reduce per-segment headers
    canp_apply_pack_v2(out->payload_arr, out->row_len, out->col_len);

    nng_id_map_free(index_map);

    void *encoded = parquet_data_alloc(out->schema, out->payload_arr, out->ts, out->col_len, out->row_len);
    if (!encoded) {
        log_error("parquet_data_alloc failed");
        canpStream_free(out);
        return NULL;
    }
    nng_free(out, sizeof(struct stream_data_out));
    return encoded;
}

// ---- helpers for canp_stream_decode (readability) ----
// Describe the lightweight view of a v2 cell to avoid copying.
struct v2_view {
	uint32_t segs;
	uint8_t  flags;
	uint32_t busid_bytes;
	const uint8_t *busid_arr;
	const uint8_t *tsdiff_arr;
	uint32_t L;
	uint32_t mask_bytes;
	const uint8_t *mask;
	uint32_t const_count;
	uint32_t var_count;
	const uint8_t *const_vals;
	const uint8_t *var_vals;
};

// Parse v2 layout: |segs(1)|flags(1)|busid(1 or segs)|tsdiff(segs)|L(1)|mask?|const?|var?|
// Return 1 on success and fill view; otherwise 0.
static int canp_cell_view_v2(const uint8_t *dbytes, uint32_t n, struct v2_view *view)
{
	if (!dbytes || n < 4 || !view) return 0;
	uint32_t pos = 0;
	uint32_t segs = dbytes[pos++];
	uint8_t flags = dbytes[pos++];
	if (segs == 0) return 0;
	uint32_t busid_bytes = (flags & 0x01) ? segs : 1;
	if (n < pos + busid_bytes + segs + 1) return 0;
	const uint8_t *busid_arr = dbytes + pos; pos += busid_bytes;
	const uint8_t *tsdiff_arr = dbytes + pos; pos += segs;
	uint32_t L = dbytes[pos++];
	uint32_t mask_bytes = (flags & 0x02) ? ((L + 7) / 8) : 0;
	if (n < pos + mask_bytes) return 0;
	const uint8_t *mask = dbytes + pos; pos += mask_bytes;
	uint32_t const_count = 0;
	if (mask_bytes) {
		for (uint32_t b = 0; b < L; b++) {
			uint8_t m = mask[b / 8];
			if (m & (uint8_t)(1u << (7 - (b % 8)))) const_count++;
		}
	}
	if (n < pos + const_count) return 0;
	const uint8_t *const_vals = dbytes + pos; pos += const_count;
	uint32_t var_count = (L >= const_count) ? (L - const_count) : 0;
	if (n < pos + var_count * segs) return 0;
	const uint8_t *var_vals = dbytes + pos;
	if (pos + var_count * segs != n) return 0;

	view->segs = segs;
	view->flags = flags;
	view->busid_bytes = busid_bytes;
	view->busid_arr = busid_arr;
	view->tsdiff_arr = tsdiff_arr;
	view->L = L;
	view->mask_bytes = mask_bytes;
	view->mask = mask;
	view->const_count = const_count;
	view->var_count = var_count;
	view->const_vals = const_vals;
	view->var_vals = var_vals;
	return 1;
}

// Extract CAN ID from schema entry like "1a2b" (4 hex chars).
static inline uint16_t parse_canid_from_schema_entry(const char *s)
{
	if (!s) return 0;
	if (strlen(s) < 4) return 0;
	unsigned int c = 0;
	if (sscanf(s, "%4x", &c) == 1) return (uint16_t)c;
	return 0;
}

// Calculate bytes contributed by one cell when expanded to v1 segments.
static uint32_t canp_calc_row_bytes_for_cell(parquet_data_packet *cell)
{
	if (!cell || !cell->data || cell->size < 1) return 0;
	const uint8_t *dbytes = cell->data;
	uint32_t n = cell->size;
	struct v2_view v;
	if (canp_cell_view_v2(dbytes, n, &v)) {
		return v.segs * (uint32_t)(6 + v.L);
	}
	if (n < 4) return 0;
	uint32_t pos = 0;
	uint32_t sum = 0;
	while (n - pos >= 4) {
		uint16_t payload_len = (uint16_t)((dbytes[pos + 2] << 8) | dbytes[pos + 3]);
		if (n - pos < (uint32_t)(4 + payload_len)) break;
		sum += (uint32_t)(6 + payload_len);
		pos += (uint32_t)(4 + payload_len);
	}
	return sum;
}

// Emit segments from one cell into output buffer using v2 if possible, otherwise v1.
static void canp_emit_from_cell(uint8_t *dst, uint32_t *pidx, parquet_data_packet *cell, uint16_t canid)
{
	if (!cell || !cell->data || cell->size < 1) return;
	const uint8_t *dbytes = cell->data;
	uint32_t n = cell->size;
	struct v2_view v;
	if (canp_cell_view_v2(dbytes, n, &v)) {
		if (v.L <= 4096) {
			uint16_t const_index_of_plane[4096];
			uint16_t var_index_of_plane[4096];
			uint32_t const_idx = 0;
			uint32_t var_idx = 0;
			for (uint32_t b = 0; b < v.L; b++) {
				int is_const = (v.mask_bytes && (v.mask[b / 8] & (uint8_t)(1u << (7 - (b % 8))))) ? 1 : 0;
				if (is_const) {
					const_index_of_plane[b] = (uint16_t)const_idx++;
					var_index_of_plane[b] = 0xFFFFu;
				} else {
					var_index_of_plane[b] = (uint16_t)var_idx++;
					const_index_of_plane[b] = 0xFFFFu;
				}
			}
			for (uint32_t sidx = 0; sidx < v.segs; sidx++) {
				uint8_t tsdiff = v.tsdiff_arr[sidx];
				uint8_t busid = (v.flags & 0x01) ? v.busid_arr[sidx] : v.busid_arr[0];
				dst[(*pidx)++] = tsdiff;
				dst[(*pidx)++] = busid;
				htobe16_mem(dst + *pidx, &canid); *pidx += 2;
				uint16_t L16 = (uint16_t)v.L;
				dst[(*pidx)++] = (uint8_t)((L16 >> 8) & 0xFF);
				dst[(*pidx)++] = (uint8_t)(L16 & 0xFF);
				for (uint32_t b = 0; b < v.L; b++) {
					if (const_index_of_plane[b] != 0xFFFFu) {
						dst[(*pidx)++] = v.const_vals[const_index_of_plane[b]];
					} else {
						uint32_t vp = var_index_of_plane[b];
						dst[(*pidx)++] = v.var_vals[vp * v.segs + sidx];
					}
				}
			}
		}
		return;
	}
	if (n < 4) return;
	uint32_t pos = 0;
	while (n - pos >= 4) {
		uint8_t tsdiff = dbytes[pos + 0];
		uint8_t busid  = dbytes[pos + 1];
		uint8_t len_h  = dbytes[pos + 2];
		uint8_t len_l  = dbytes[pos + 3];
		uint16_t payload_len = (uint16_t)((len_h << 8) | len_l);
		if (n - pos < (uint32_t)(4 + payload_len)) break;
		dst[(*pidx)++] = tsdiff;
		dst[(*pidx)++] = busid;
		htobe16_mem(dst + *pidx, &canid); *pidx += 2;
		dst[(*pidx)++] = len_h;
		dst[(*pidx)++] = len_l;
		memcpy(dst + *pidx, dbytes + pos + 4, payload_len);
		*pidx += payload_len;
		pos += (uint32_t)(4 + payload_len);
	}
}

//|ts|len| (tsdiff|busid|canid|len|payload)*
static struct stream_decoded_data *canp_stream_decode(struct parquet_data_ret *p)
{
	log_error("canp_stream_decode start");
	if (!p) return NULL;
	struct stream_decoded_data *d = nng_alloc(sizeof(struct stream_decoded_data));
	if (!d) return NULL;
	d->data = NULL;
	d->len = 0;

	uint32_t *row_len = nng_alloc(sizeof(uint32_t) * p->row_len);
	if (!row_len) {
		nng_free(d, sizeof(struct stream_decoded_data));
		log_error("canp_stream_decode row_len is NULL");
		return NULL;
	}
	for (uint32_t i = 0; i < p->row_len; i++) {
		uint32_t sum = 0;
		for (uint32_t j = 0; j < p->col_len; j++) {
			sum += canp_calc_row_bytes_for_cell(p->payload_arr[j][i]);
		}
		row_len[i] = sum;
		if (sum != 0) {
			// Row header: ts(8) + len(4)
			d->len += 12 + sum;
		}
	}
	if (d->len == 0) {
		nng_free(d, sizeof(struct stream_decoded_data));
		nng_free(row_len, sizeof(uint32_t) * p->row_len);
		log_error("canp_stream_decode d->len is 0");
		return NULL;
	}

	d->data = nng_alloc(d->len);
	if (!d->data) {
		nng_free(d, sizeof(struct stream_decoded_data));
		nng_free(row_len, sizeof(uint32_t) * p->row_len);
		log_error("canp_stream_decode d->data is NULL");
		return NULL;
	}

	uint32_t idx = 0;
	for (uint32_t i = 0; i < p->row_len; i++) {
		if (row_len[i] == 0) continue;
		// row header
		htobe64_mem((uint8_t *)d->data + idx, &p->ts[i]); idx += 8;
		htobe32_mem((uint8_t *)d->data + idx, &row_len[i]); idx += 4;
		// row payload
		for (uint32_t j = 0; j < p->col_len; j++) {
			parquet_data_packet *cell = p->payload_arr[j][i];
			if (!cell || cell->size < 1) continue;
			uint16_t canid = parse_canid_from_schema_entry((p->schema && j < p->col_len) ? p->schema[j] : NULL);
			canp_emit_from_cell((uint8_t *)d->data, &idx, cell, canid);
		}
	}
	nng_free(row_len, sizeof(uint32_t) * p->row_len);

	return d;
}

void *canp_decode(void *data)
{
    struct parquet_data_ret *p = (struct parquet_data_ret *)data;
    if (!p) return NULL;
    return canp_stream_decode(p);
}

void *canp_encode(void *data)
{
    return canpStream_init(data);
}

static int checkInput(const char *input,
                      uint32_t *start_key_index,
                      uint32_t *end_key_index,
                      uint32_t *schema_index)
{
    int count = 0;
    *start_key_index = 0;
    *end_key_index = 0;
    *schema_index = 0;
    if (strncmp(input, "sync", 4) != 0 && strncmp(input, "async", 5) != 0) {
        log_error("Error: Invalid input format\n");
        return -1;
    }
    for (unsigned int i = 0; i < strlen(input); i++) {
        if (input[i] == '-') {
            if (count == 0) {
                *start_key_index = i + 1;
            } else if (count == 1) {
                *end_key_index = i + 1;
            } else if (count == 2) {
                *schema_index = i + 1;
            }
            count++;
        }
    }
    if (count != 2 && count != 3) {
        log_error("Error: Invalid input format\n");
        return -1;
    }
    for (unsigned int i = *start_key_index; i < *end_key_index - 1; i++) {
        if (input[i] < '0' || input[i] > '9') {
            log_error("Error: Invalid input format\n");
            return -1;
        }
    }
    for (unsigned int i = *end_key_index; i < (*schema_index == 0 ? strlen(input) : *schema_index - 1); i++) {
        if (input[i] < '0' || input[i] > '9') {
            log_error("Error: Invalid input format\n");
            return -1;
        }
    }
    return 0;
}

static char **schema_parse(const char *schema_str, uint32_t schema_str_len, uint32_t *schema_len)
{
    char **schema = NULL;
    *schema_len = schema_str_len / 4;
    schema = nng_alloc(sizeof(char *) * (*schema_len));
    if (!schema) return NULL;
    for (uint32_t i = 0; i < *schema_len; i++) {
        schema[i] = nng_alloc(5);
        if (!schema[i]) {
            schema_free(schema, i);
            return NULL;
        }
        memcpy(schema[i], schema_str + i * 4, 4);
        schema[i][4] = '\0';
    }
    return schema;
}

static struct cmd_data *parse_input_cmd(const char *input)
{
    struct cmd_data *cmd = (struct cmd_data *)nng_alloc(sizeof(struct cmd_data));
    if (!cmd) return NULL;
    cmd->schema = NULL;
    cmd->schema_len = 0;

    uint32_t s = 0, e = 0, k = 0;
    if (checkInput(input, &s, &e, &k) != 0) {
        nng_free(cmd, sizeof(struct cmd_data));
        return NULL;
    }
    cmd->is_sync = (strncmp(input, "sync", 4) == 0);
    cmd->start_key = (uint64_t)atoll(input + s);
    cmd->end_key = (uint64_t)atoll(input + e);
    if (k != 0) {
        cmd->schema = schema_parse(input + k, strlen(input) - k, &cmd->schema_len);
    }
    log_info("start_key: %ld end_key: %ld schema_len: %d", cmd->start_key, cmd->end_key, cmd->schema_len);
    return cmd;
}

void *canp_cmd_parser(void *data)
{
    return parse_input_cmd((const char *)data);
}

int canp_plugin_init()
{
    int ret = 0;
    char *name = (char *)malloc(strlen(CANP_STREAM_NAME) + 1);
    if (name == NULL) {
        return -1;
    }
    strcpy(name, CANP_STREAM_NAME);
    ret = stream_register(name, CANP_STREAM_ID, canp_decode, canp_encode, canp_cmd_parser);
    if (ret != 0) {
        log_error("stream_register %s failed", name);
        free(name);
        return -1;
    }
    return ret;
}
