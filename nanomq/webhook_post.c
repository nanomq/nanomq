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

#include <base64.h>
#include <cJSON.h>

int
webhook_msg_publish(nng_socket *sock, conf_web_hook *hook_conf,
    pub_packet_struct *pub_packet, const char *username, const char *client_id)
{
	if (!hook_conf->enable) {
		return -1;
	}

	cJSON *obj = cJSON_CreateObject();
	cJSON_AddNumberToObject(obj, "ts", nng_clock());
	cJSON_AddStringToObject(
	    obj, "topic", pub_packet->var_header.publish.topic_name.body);
	cJSON_AddBoolToObject(obj, "retain", pub_packet->fixed_header.retain);
	cJSON_AddNumberToObject(obj, "qos", pub_packet->fixed_header.qos);
	cJSON_AddStringToObject(obj, "action", "message_publish");
	if (username) {
		cJSON_AddStringToObject(obj, "from_username", username);
	} else {
		cJSON_AddNullToObject(obj, "from_username");
	}
	if (client_id) {
		cJSON_AddStringToObject(obj, "from_client_id", client_id);
	} else {
		cJSON_AddNullToObject(obj, "from_client_id");
	}
	size_t out_size = 0;
	char * encode   = NULL;
	switch (hook_conf->encode_payload) {
	case plain:
		cJSON_AddStringToObject(
		    obj, "payload", (const char *) pub_packet->payload.data);
		/* code */
		break;
	case base64:
		BASE64_ENCODE_OUT_SIZE(pub_packet->payload.len);
		encode = nng_zalloc(out_size);
		base64_encode(
		    pub_packet->payload.data, pub_packet->payload.len, encode);
		cJSON_AddStringToObject(obj, "payload", encode);
		nng_strfree(encode);
		/* code */
		break;
	case base62:
		/* code */
		// TODO add base62 support
		break;

	default:
		break;
	}

	char *json = cJSON_PrintUnformatted(obj);

	int rv = nng_send(*sock, json, strlen(json), 0);

	nng_strfree(json);
	cJSON_Delete(obj);

	return rv;
}