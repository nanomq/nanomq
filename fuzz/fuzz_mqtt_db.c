#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "nng/nng.h"
#include "nng/supplemental/nanolib/mqtt_db.h"

// Simple way to consume data
typedef struct {
    const uint8_t *data;
    size_t size;
    size_t pos;
} buffer_t;

uint8_t read_u8(buffer_t *buf) {
    if (buf->pos >= buf->size) return 0;
    return buf->data[buf->pos++];
}

uint32_t read_u32(buffer_t *buf) {
    if (buf->pos + 4 > buf->size) return 0;
    uint32_t v = 0;
    memcpy(&v, buf->data + buf->pos, 4);
    buf->pos += 4;
    return v;
}

char *read_string(buffer_t *buf) {
    if (buf->pos >= buf->size) return NULL;
    size_t len = read_u8(buf);
    if (buf->pos + len > buf->size) return NULL;
    char *str = malloc(len + 1);
    if (!str) return NULL;
    memcpy(str, buf->data + buf->pos, len);
    str[len] = '\0';
    buf->pos += len;
    return str;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    dbtree *db = NULL;
    dbtree_create(&db);
    if (!db) return 0;

    buffer_t buf = {data, size, 0};

    while (buf.pos < buf.size) {
        uint8_t op = read_u8(&buf) % 3;
        char *topic = read_string(&buf);
        if (!topic) break;

        switch (op) {
            case 0: // Insert
                {
                    uint32_t id = read_u32(&buf);
                    dbtree_insert_client(db, topic, id);
                }
                break;
            case 1: // Find
                {
                    uint32_t *clients = dbtree_find_clients(db, topic);
                    if (clients) {
                        cvector_free(clients);
                    }
                }
                break;
            case 2: // Delete
                {
                    uint32_t id = read_u32(&buf);
                    dbtree_delete_client(db, topic, id);
                }
                break;
        }
        free(topic);
    }

    dbtree_destory(db);
    return 0;
}
