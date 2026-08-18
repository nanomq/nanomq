//
// Copyright 2026 NanoMQ Team, Inc. <jaylin@emqx.io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "include/webhook_post.h"
#include "include/pub_handler.h"

#include "nng/supplemental/util/platform.h"
#include "nng/supplemental/nanolib/nmq_base64.h"
#include "nng/supplemental/nanolib/cJSON.h"
#include "nng/protocol/mqtt/mqtt_parser.h"
#include "nng/supplemental/nanolib/log.h"

static bool event_filter(conf_web_hook *hook_conf, webhook_event event);
static bool event_filter_with_topic(
    conf_web_hook *hook_conf, webhook_event event, const char *topic);
static void         set_char(char *out, size_t *index,  size_t outlen, char c);
static size_t       base64_no_padding_encode(
    const unsigned char *in, size_t inlen, char *out, size_t outlen);

static size_t       base62_encode(
    const unsigned char *in, size_t inlen, char *out, size_t outlen);

#define BASE62_ENCODE_OUT_SIZE(s)                                       \
    (((uint64_t)(s) > (((uint64_t)SIZE_MAX - 4) / 135) * 100)           \
        ? 0                                                             \
        : (size_t) (((((uint64_t)(s)) * 135) / 100) + 4))

#define BASE64_NO_PADDING_ENCODE_OUT_SIZE(s)                            \
    (((uint64_t)(s) > (((uint64_t)SIZE_MAX - 2) / 8) * 6)               \
        ? 0                                                             \
        : (size_t) (((((uint64_t)(s)) * 8) / 6) + 2))

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
set_char(char *out, size_t *index, size_t outlen, char c)
{
	size_t idx = *index;
	if (idx >= outlen - 1) {
		return;
	}

	switch (c) {
	case 'i':
		out[idx++] = 'i';
		break;
	case '+':
		out[idx++] = 'A';
		break;
	case '/':
		out[idx++] = 'B';
		break;
	default:
		out[idx++] = c;
		break;
	}
	*index = idx;
}

static size_t
base62_encode(const unsigned char *in, size_t inlen, char *out, size_t outlen)
{
    const char *alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    if (inlen == 0 || out == NULL || outlen == 0) {
        return 0;
    }

    size_t zeros = 0;
    while (zeros < inlen && in[zeros] == 0) {
        zeros++;
    }

    unsigned char *tmp = nng_alloc(inlen);
    if (tmp == NULL) {
        return 0;
    }
    memcpy(tmp, in, inlen);

    size_t out_idx = 0;
    size_t start_idx = zeros;

    while (start_idx < inlen) {
        unsigned int remainder = 0;
        for (size_t i = start_idx; i < inlen; i++) {
            unsigned int dividend = (remainder << 8) | tmp[i];
            tmp[i] = (unsigned char)(dividend / 62);
            remainder = dividend % 62;
        }

        if (out_idx >= outlen - 1) {
            nng_free(tmp, inlen);
            return 0;
        }
        out[out_idx++] = alphabet[remainder];

        while (start_idx < inlen && tmp[start_idx] == 0) {
            start_idx++;
        }
    }

    for (size_t i = 0; i < zeros; i++) {
        if (out_idx >= outlen - 1) {
            nng_free(tmp, inlen);
            return 0;
        }
        out[out_idx++] = alphabet[0];
    }

    for (size_t i = 0; i < out_idx / 2; i++) {
        char t = out[i];
        out[i] = out[out_idx - 1 - i];
        out[out_idx - 1 - i] = t;
    }

    out[out_idx] = '\0';
    nng_free(tmp, inlen);
    return out_idx;
}

static size_t
base64_no_padding_encode(const unsigned char *in, size_t inlen, char *out, size_t outlen)
{
	size_t i, j;
	size_t pos = 0, val = 0;
	const char   base62en[] =
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	if (inlen == 0 || out == NULL || outlen == 0) {
		return 0;
	}

	for (i = j = 0; i < inlen; i++) {
		val = (val << 8) | (in[i] & 0xFF);
		pos += 8;
		while (pos > 5) {
			char c = base62en[val >> (pos -= 6)];
			set_char(out, &j, outlen, c);
			val &= ((1 << pos) - 1);
		}
	}
	if (pos > 0) {
		char c = base62en[val << (6 - pos)];
		set_char(out, &j, outlen, c);
	}
	if (j < outlen) {
		out[j] = '\0';
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
		out_size = BASE64_ENCODE_OUT_SIZE((uint64_t)pub_packet->payload.len);
		encode = nng_zalloc(out_size);
		len    = nmq_base64_encode(
		    (const uint8_t *) pub_packet->payload.data,
		    pub_packet->payload.len, encode, out_size);
		if (len > 0) {
			cJSON_AddStringToObject(obj, "payload", encode);
		} else {
			cJSON_AddNullToObject(obj, "payload");
		}
		nng_strfree(encode);
		break;
	case base64_no_padding:
		out_size = BASE64_NO_PADDING_ENCODE_OUT_SIZE(pub_packet->payload.len);
		encode   = nng_zalloc(out_size);
		len      = base64_no_padding_encode(
		         pub_packet->payload.data, pub_packet->payload.len, encode, out_size);
		if (len > 0) {
			cJSON_AddStringToObject(obj, "payload", encode);
		} else {
			cJSON_AddNullToObject(obj, "payload");
		}
		nng_strfree(encode);
		break;
	case base62:
		out_size = BASE62_ENCODE_OUT_SIZE(pub_packet->payload.len);
		if (out_size == 0) {
			log_error("Payload is too large for Base62 encoding.");
			len = 0;
		} else {
			encode   = nng_zalloc(out_size);
			len      = base62_encode(
                 pub_packet->payload.data, pub_packet->payload.len, encode, out_size);
		}
        if (len > 0) {
            cJSON_AddStringToObject(obj, "payload", encode);
        } else {
            // Handle empty payload or alloc failure
            if (pub_packet->payload.len == 0) {
                 cJSON_AddStringToObject(obj, "payload", "");
            } else {
                 cJSON_AddNullToObject(obj, "payload");
            }
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

static uint32_t g_inc_id = 0;

inline int
hook_entry(nano_work *work, uint8_t reason)
{
	int            rv        = 0;
	conf_web_hook *hook_conf = &work->config->web_hook;
	conn_param    *cparam    = work->cparam;
	nng_socket    *sock      = &work->hook_sock;

	//BLF & Parquet is discarded, only serve in commercial ver
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
		break;
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