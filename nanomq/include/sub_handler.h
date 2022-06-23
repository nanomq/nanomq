#ifndef MQTT_SUBSCRIBE_HANDLE_H
#define MQTT_SUBSCRIBE_HANDLE_H

#include <nng/nng.h>
#include <nng/mqtt/packet.h>

#include "broker.h"

typedef struct {
	uint32_t pid;
	dbtree *db;
}  sub_destroy_info;

int decode_sub_msg(nano_work *);
int encode_suback_msg(nng_msg *, nano_work *);
int sub_ctx_handle(nano_work *);
// free mem about one topic in sub_ctx
void sub_ctx_del(void *, char *, uint32_t);
// free all mem about sub_ctx
void sub_ctx_free(client_ctx *);
void sub_pkt_free(packet_subscribe *);
void destroy_sub_client(uint32_t pid, dbtree * db);

#endif
