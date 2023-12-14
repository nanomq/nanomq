//
// Copyright 2020 NanoMQ Team, Inc. <jaylin@emqx.io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "include/webhook_post.h"
#include "include/pub_handler.h"

#include "nng/supplemental/util/platform.h"
#include "nng/supplemental/nanolib/base64.h"
#include "nng/supplemental/nanolib/cJSON.h"
#include "nng/protocol/mqtt/mqtt_parser.h"
#include "nng/supplemental/nanolib/log.h"

static bool event_filter(conf_web_hook *hook_conf, webhook_event event);
static bool event_filter_with_topic(
    conf_web_hook *hook_conf, webhook_event event, const char *topic);
static void         set_char(char *out, unsigned int *index, char c);
static unsigned int base62_encode(
    const unsigned char *in, unsigned int inlen, char *out);

static int flush_smsg_to_disk(nng_msg **smsg, size_t len, void *handle, nng_aio *aio);

#define BASE62_ENCODE_OUT_SIZE(s) ((unsigned int) ((((s) * 8) / 6) + 2))

static bool
event_filter(conf_web_hook *hook_conf, webhook_event event)
{
	for (uint16_t i = 0; i < hook_conf->rule_count; i++) {
		if (hook_conf->rules[i]->event == event) {
			return true;
		}
	}

	return false;
}

static bool
event_filter_with_topic(
    conf_web_hook *hook_conf, webhook_event event, const char *topic)
{
	for (uint16_t i = 0; i < hook_conf->rule_count; i++) {
		if (hook_conf->rules[i]->event == event) {
			if (hook_conf->rules[i]->topic != NULL) {
				if (!topic_filter(
				        hook_conf->rules[i]->topic, topic)) {
					continue;
				}
			}
			return true;
		}
	}

	return false;
}

static void
set_char(char *out, unsigned int *index, char c)
{
	unsigned int idx = *index;
	switch (c) {
	case 'i':
		out[idx++] = 'i';
		// out[idx++] = 'a';
		break;
	case '+':
		// out[idx++] = 'i';
		// out[idx++] = 'b';
		out[idx++] = 'A';
		break;
	case '/':
		// out[idx++] = 'i';
		// out[idx++] = 'c';
		out[idx++] = 'B';
		break;
	default:
		out[idx++] = c;
		break;
	}

	*index = idx;
}

static unsigned int
base62_encode(const unsigned char *in, unsigned int inlen, char *out)
{
	unsigned int i;
	unsigned int j;
	unsigned int pos = 0, val = 0;
	const char   base62en[] =
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	for (i = j = 0; i < inlen; i++) {
		val = (val << 8) | (in[i] & 0xFF);
		pos += 8;
		while (pos > 5) {
			char c = base62en[val >> (pos -= 6)];
			set_char(out, &j, c);
			val &= ((1 << pos) - 1);
		}
	}
	if (pos > 0) {
		char c = base62en[val << (6 - pos)];
		set_char(out, &j, c);
	}
	return j;
}

int
webhook_msg_publish(nng_socket *sock, conf_web_hook *hook_conf,
    pub_packet_struct *pub_packet, const char *username, const char *client_id)
{
	if (!hook_conf->enable ||
	    !event_filter_with_topic(hook_conf, MESSAGE_PUBLISH,
	        pub_packet->var_header.publish.topic_name.body)) {
		return -1;
	}

	cJSON *obj = cJSON_CreateObject();
	
	cJSON_AddNumberToObject(obj, "ts", nng_timestamp());
	cJSON_AddStringToObject(
	    obj, "topic", pub_packet->var_header.publish.topic_name.body);
	cJSON_AddBoolToObject(obj, "retain", pub_packet->fixed_header.retain);
	cJSON_AddNumberToObject(obj, "qos", pub_packet->fixed_header.qos);
	cJSON_AddStringToObject(obj, "action", "message_publish");
	cJSON_AddStringToObject(
	    obj, "from_username", username == NULL ? "undefined" : username);
	if (client_id) {
		cJSON_AddStringToObject(obj, "from_client_id", client_id);
	} else {
		cJSON_AddNullToObject(obj, "from_client_id");
	}
	size_t out_size = 0;
	char  *encode   = NULL;
	size_t len      = 0;
	switch (hook_conf->encode_payload) {
	case plain:
		cJSON_AddStringToObject(
		    obj, "payload", (const char *) pub_packet->payload.data);
		break;
	case base64:
		out_size = BASE64_ENCODE_OUT_SIZE(pub_packet->payload.len);
		encode   = nng_zalloc(out_size);
		len      = base64_encode(
		         pub_packet->payload.data, pub_packet->payload.len, encode);
		if (len > 0) {
			cJSON_AddStringToObject(obj, "payload", encode);
		} else {
			cJSON_AddNullToObject(obj, "payload");
		}
		nng_strfree(encode);
		break;
	case base62:
		out_size = BASE62_ENCODE_OUT_SIZE(pub_packet->payload.len);
		encode   = nng_zalloc(out_size);
		len      = base62_encode(
		         pub_packet->payload.data, pub_packet->payload.len, encode);
		if (len > 0) {
			cJSON_AddStringToObject(obj, "payload", encode);
		} else {
			cJSON_AddNullToObject(obj, "payload");
		}
		nng_strfree(encode);
		break;

	default:
		break;
	}

	char *json = cJSON_PrintUnformatted(obj);

	int rv = nng_send(*sock, json, strlen(json), NNG_FLAG_NONBLOCK);

	nng_strfree(json);
	cJSON_Delete(obj);

	return rv;
}

int
webhook_client_connack(nng_socket *sock, conf_web_hook *hook_conf,
    uint8_t proto_ver, uint16_t keepalive, uint8_t reason,
    const char *username, const char *client_id)
{
	if (!hook_conf->enable || !event_filter(hook_conf, CLIENT_CONNACK)) {
		return -1;
	}

	cJSON *obj = cJSON_CreateObject();

	cJSON_AddNumberToObject(obj, "proto_ver", proto_ver);
	cJSON_AddNumberToObject(obj, "keepalive", keepalive);
	// TODO get reason string
	cJSON_AddStringToObject(
	    obj, "conn_ack", reason == SUCCESS ? "success" : "fail");
	cJSON_AddStringToObject(
	    obj, "username", username == NULL ? "undefined" : username);
	cJSON_AddStringToObject(obj, "clientid", client_id);
	cJSON_AddStringToObject(obj, "action", "client_connack");

	char *json = cJSON_PrintUnformatted(obj);

	int rv = nng_send(*sock, json, strlen(json), NNG_FLAG_NONBLOCK);

	nng_strfree(json);
	cJSON_Delete(obj);

	return rv;
}

int
webhook_client_disconnect(nng_socket *sock, conf_web_hook *hook_conf,
    uint8_t proto_ver, uint16_t keepalive, uint8_t reason,
    const char *username, const char *client_id)
{
	if (!hook_conf->enable ||
	    !event_filter(hook_conf, CLIENT_DISCONNECTED)) {
		return -1;
	}

	cJSON *obj = cJSON_CreateObject();
	// TODO get reason string
	cJSON_AddStringToObject(
	    obj, "reason", reason == SUCCESS ? "normal" : "abnormal");
	cJSON_AddStringToObject(
	    obj, "username", username == NULL ? "undefined" : username);
	cJSON_AddStringToObject(obj, "clientid", client_id);
	cJSON_AddStringToObject(obj, "action", "client_disconnected");

	char *json = cJSON_PrintUnformatted(obj);

	int rv = nng_send(*sock, json, strlen(json), NNG_FLAG_NONBLOCK);

	nng_strfree(json);
	cJSON_Delete(obj);

	return rv;
}

static uint32_t g_msg_index = 0;

inline int
hook_entry(nano_work *work, uint8_t reason)
{
	int            rv        = 0;
	conf_web_hook *hook_conf = &work->config->web_hook;
	conf_exchange *ex_conf   = &work->config->exchange;
	conn_param    *cparam    = work->cparam;
	nng_socket    *sock      = &work->webhook_sock;
	nng_socket    *ex_sock;

	// process MQ msg first, only pub msg is valid
	// CMD_PUBLISHV5?
	if (ex_conf->count > 0 && nng_msg_get_type(work->msg) == CMD_PUBLISH &&
	    work->flag == CMD_PUBLISH) {
		// dup msg for now, TODO or reuse it?
		nng_msg *msg;
		nng_msg_alloc(&msg, 0);
		nng_msg_header_append(msg, nng_msg_header(work->msg), nng_msg_header_len(work->msg));
		nng_msg_append(msg, nng_msg_body(work->msg), nng_msg_len(work->msg));
		uint8_t *body_ptr = nng_msg_body(work->msg);
		ptrdiff_t offset = (ptrdiff_t)(nng_msg_payload_ptr(work->msg) - body_ptr);
		nng_msg_set_payload_ptr(msg, (uint8_t *)nng_msg_body(msg) + offset);
		// nng_msg_dup(&msg, work->msg);
		for (size_t i = 0; i < ex_conf->count; i++) {
			if (topic_filter(ex_conf->nodes[i]->exchange->topic,
			        work->pub_packet->var_header.publish.topic_name.body)) {

				if (work->ctx.id > work->config->parallel)
					log_error("parallel %d idx %d", work->config->parallel);

				nng_aio *aio = hook_conf->saios[work->ctx.id-1];
				int     *nkey = nng_alloc(sizeof(int));

				nng_mtx_lock(hook_conf->ex_mtx);
				*nkey = g_msg_index++;
				nng_mtx_unlock(hook_conf->ex_mtx);

				if (nng_aio_busy(aio))
					nng_aio_wait(aio);

				nng_aio_set_prov_data(aio, (void *) nkey);
				nng_aio_set_msg(aio, msg);

				ex_sock = ex_conf->nodes[i]->sock;
				nng_send_aio(*ex_sock, aio);
				if (g_msg_index % 2000 == 0)
					printf("%d msgs in exchange\n", g_msg_index);
				break;
			}
		}
	}
	if (!hook_conf->enable)
		return 0;
	switch (work->flag) {
	case CMD_CONNACK:
		rv = webhook_client_connack(sock, hook_conf,
		    conn_param_get_protover(cparam),
		    conn_param_get_keepalive(cparam), reason,
		    (const char*)conn_param_get_username(cparam),
		    (const char*)conn_param_get_clientid(cparam));
		break;
	case CMD_PUBLISH:
		rv = webhook_msg_publish(sock, hook_conf, work->pub_packet,
		    (const char*)conn_param_get_username(cparam),
		    (const char*)conn_param_get_clientid(cparam));
		break;
	case CMD_DISCONNECT_EV:
		rv = webhook_client_disconnect(sock, hook_conf,
		    conn_param_get_protover(cparam),
		    conn_param_get_keepalive(cparam), reason,
		    (const char*)conn_param_get_username(cparam),
		    (const char*)conn_param_get_clientid(cparam));
	case CMD_SUBSCRIBE:
		break;
	case CMD_UNSUBSCRIBE:
		break;
	default:
		break;
	}
	// Do not let online event msg trigger webhook
	work->flag = 0;
	return rv;
}

static int
flush_smsg_to_disk(nng_msg **smsg, size_t len, void *handle, nng_aio *aio)
{
	nng_msg * msg;
	void    **datas;
	uint32_t *keys;
	size_t   *lens;

	if (false == nng_aio_begin(aio)) {
		log_error("nng aio begin failed");
		return NNG_EBUSY;
	}

	keys = nng_alloc(sizeof(uint32_t)* len);
	datas = nng_alloc(sizeof(void *) * len);
	lens = nng_alloc(sizeof(size_t) * len);
	if (!datas || !keys || !lens)
		return NNG_ENOMEM;

	int len2 = 0;
	for (int i=0; i<(int)len; ++i) {
		msg = smsg[i];
		if (msg == NULL)
			continue;
		datas[len2] = nng_msg_payload_ptr(msg);
		lens[len2] = nng_msg_len(msg) -
		        (nng_msg_payload_ptr(msg) - (uint8_t *)nng_msg_body(msg));
		keys[len2] = *(uint32_t *)nng_msg_get_proto_data(msg);
		len2 ++;
	}

	log_error("ready to flush");
	// write to disk
	// parquet_write_batch(handle, keys, datas, lens, len2, aio);
	// finish aio after flushing to disk
	nng_free(smsg, len);
	return 0;
}

static void
send_exchange_cb(void *arg)
{
	struct work *w = arg;

	conf *nanomq_conf = w->config;
	conf_web_hook *hook_conf = &nanomq_conf->web_hook;

	nng_aio *aio = hook_conf->saios[w->ctx.id-1];

	if (nng_aio_result(aio) != 0) {
		log_error("error in send to exchange");
		return;
	}

	nng_msg *msg = nng_aio_get_msg(aio);
	if (!msg)
		return;

	nng_msg **msgs_del = nng_aio_get_prov_data(aio);
	if (!msgs_del)
		return;

	int *msgs_lenp = (int *)nng_msg_get_proto_data(msg);
	int  msgs_len;
	if (msgs_lenp)
		msgs_len = *msgs_lenp;

	// Flush to disk. TODO Ask Parquet
	nng_mtx_lock(hook_conf->ex_mtx);
	flush_smsg_to_disk(msgs_del, msgs_len, NULL, hook_conf->ex_aio);
	nng_mtx_unlock(hook_conf->ex_mtx);

	nng_msg_free(msg);
	if (msgs_lenp)
		nng_free(msgs_lenp, sizeof(int));
}

int
hook_exchange_init(conf *nanomq_conf, uint64_t num_ctx)
{
	conf_web_hook *hook_conf = &nanomq_conf->web_hook;

	nng_mtx_alloc(&hook_conf->ex_mtx);
	nng_aio_alloc(&hook_conf->ex_aio, NULL, NULL);
	hook_conf->saios = nng_alloc(sizeof(nng_aio *) * num_ctx);

	return 0;
}

int
hook_exchange_sender_init(conf *nanomq_conf, struct work **works, uint64_t num_ctx)
{
	conf_web_hook *hook_conf = &nanomq_conf->web_hook;

	for (int i=0; i<num_ctx; ++i) {
		nng_aio_alloc(&hook_conf->saios[i], send_exchange_cb, works[i]);
	}

	return 0;
}

