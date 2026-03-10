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
#include "nng/supplemental/nanolib/base64.h"
#include "nng/supplemental/nanolib/cJSON.h"
#include "nng/protocol/mqtt/mqtt_parser.h"
#include "nng/supplemental/nanolib/log.h"

static bool event_filter(conf_web_hook *hook_conf, webhook_event event);
static bool event_filter_with_topic(
    conf_web_hook *hook_conf, webhook_event event, const char *topic);
static void         set_char(char *out, unsigned int *index, char c);
static unsigned int base64_no_padding_encode(
    const unsigned char *in, unsigned int inlen, char *out);

#define BASE64_NO_PADDING_ENCODE_OUT_SIZE(s) ((unsigned int) ((((s) * 8) / 6) + 2))

// Base62 expansion factor: log2(256) / log2(62) ≈ 1.343
// We use 1.35 to be safe, plus margin for null terminator.
#define BASE62_ENCODE_OUT_SIZE(s) ((unsigned int) (((s) * 135) / 100) + 4)

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
    // Standard GMP-style alphabet (0-9, A-Z, a-z)
    // You can swap this string to "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    // if you prefer the Inverted style, but this is the most common.
    const char *alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    if (inlen == 0 || out == NULL) {
        return 0;
    }

    // 1. Count leading zeros (to preserve them in encoding if desired,
    // similar to Base58. If purely numerical, you can skip this).
    // For general payloads, preserving leading zeros is usually safer.
    unsigned int zeros = 0;
    while (zeros < inlen && in[zeros] == 0) {
        zeros++;
    }

    // 2. Create a mutable copy of the input for division
    // We allocate on heap because stack size might be limited for large payloads
    unsigned char *tmp = nng_alloc(inlen);
    if (tmp == NULL) {
        return 0;
    }
    memcpy(tmp, in, inlen);

    unsigned int out_idx = 0;
    unsigned int start_idx = zeros;

    // 3. Perform Repeated Division by 62
    while (start_idx < inlen) {
        unsigned int remainder = 0;

        // Divide the "Big Integer" represented by tmp by 62
        for (unsigned int i = start_idx; i < inlen; i++) {
            unsigned int dividend = (remainder << 8) | tmp[i];
            tmp[i] = (unsigned char)(dividend / 62);
            remainder = dividend % 62;
        }

        // The remainder is the next Base62 digit (Least Significant first)
        out[out_idx++] = alphabet[remainder];

        // Update start_idx to skip newly created leading zeros in tmp
        while (start_idx < inlen && tmp[start_idx] == 0) {
            start_idx++;
        }
    }

    // 4. Add preserved leading zeros (mapped to the first char of alphabet '0')
    // This is optional but recommended for binary data restoration.
    for (unsigned int i = 0; i < zeros; i++) {
        out[out_idx++] = alphabet[0];
    }

    // 5. Reverse the string (We generated LSD first)
    for (unsigned int i = 0; i < out_idx / 2; i++) {
        char t = out[i];
        out[i] = out[out_idx - 1 - i];
        out[out_idx - 1 - i] = t;
    }

    out[out_idx] = '\0'; // Null terminate

    nng_free(tmp, inlen);
    return out_idx;
}

static unsigned int
base64_no_padding_encode(const unsigned char *in, unsigned int inlen, char *out)
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
	case base64_no_padding:
		out_size = BASE64_NO_PADDING_ENCODE_OUT_SIZE(pub_packet->payload.len);
		encode   = nng_zalloc(out_size);
		len      = base64_no_padding_encode(
		         pub_packet->payload.data, pub_packet->payload.len, encode);
		if (len > 0) {
			cJSON_AddStringToObject(obj, "payload", encode);
		} else {
			cJSON_AddNullToObject(obj, "payload");
		}
		nng_strfree(encode);
		break;
	case base62:
        // Use the new mathematical macro
        out_size = BASE62_ENCODE_OUT_SIZE(pub_packet->payload.len);
        encode   = nng_zalloc(out_size);
        len = base62_encode(
                 pub_packet->payload.data, pub_packet->payload.len, encode);
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