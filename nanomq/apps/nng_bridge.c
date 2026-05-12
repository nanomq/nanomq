//
// Copyright 2024 NanoMQ Team, Inc. <jaylin@emqx.io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//
#include "include/nng_bridge.h"
#include "nng/nng.h"
#include "nng/protocol/mqtt/mqtt.h"
#include "nng/supplemental/nanolib/log.h"
#include "nng/supplemental/util/platform.h"
#include "nng/supplemental/nanolib/topics.h"
#include "nng/supplemental/nanolib/utils.h"
#include "nng/protocol/mqtt/mqtt_parser.h"
#include "nng/protocol/pubsub0/sub.h"
#include "nng/protocol/pubsub0/pub.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "include/nanomq.h"
#include "include/mqtt_api.h"

int
nng_proxy_sub_init(conf_nng_sub_node *node, nano_work *work)
{
    int rv = 0;

    nng_socket *sub_sock = &node->sub_sock;
    if ((rv = nng_sub0_open(sub_sock)) != 0) {
        return rv;
    }
    conn_param_alloc(&node->client);
    conn_param_set_clientid(node->client, node->clientid);
    conn_param_set_username(node->client, "nngproxy_bridge");
    conn_param_set_proto_ver(node->client, MQTT_PROTOCOL_VERSION_v311);

    if ((rv = nng_ctx_open(
                &work->extra_ctx, *sub_sock)) != 0) {
        NANO_NNG_FATAL("nng_ctx_open in nng_proxy sub", rv);
    }
    for (size_t i = 0; i < node->inwards_count; i++) {
        rv = nng_ctx_set(work->extra_ctx, NNG_OPT_SUB_SUBSCRIBE,
            node->sub_list[i]->remote_topic, node->sub_list[i]->remote_topic_len);
        if (rv != 0) {
            fatal("Unable to subscribe to topic: %s", nng_strerror(rv));
        }
    }
    // bind virtual client with work
	work->cparam = node->client;
	if ((rv = nng_listen(node->sub_sock, node->sub_url, NULL, 0)) != 0) {
		NANO_NNG_FATAL("nng_listen proxy url failed" , rv);
	}
    return 0;
}

int
nng_proxy_pub_init(conf_nng_pub_node *node)
{
    int rv = 0;

    nng_socket *pub_sock = &node->pub_sock;
    if ((rv = nng_pub0_open(pub_sock)) != 0) {
        return rv;
    }
    conn_param_alloc(&node->client);
    conn_param_set_clientid(node->client, node->clientid);
    conn_param_set_username(node->client, "nngproxy_bridge");
    conn_param_set_proto_ver(node->client, MQTT_PROTOCOL_VERSION_v311);
	if ((rv = nng_listen(node->pub_sock, node->pub_url, NULL, 0)) != 0) {
		NANO_NNG_FATAL("nng_listen proxy url failed" , rv);
	}
    return 0;
}

void
nng_pub_handler(nano_work *work, nng_msg *nmsg)
{
	int      rv    = 0;
	// Or we just exclude all topic with $?
	if ((work->pub_packet->var_header.publish.topic_name.len > strlen("$SYS")) &&
		strncmp(work->pub_packet->var_header.publish.topic_name.body, "$SYS", strlen("$SYS")) == 0) {
		return;
	}
    mqtt_string *sub_topic = &work->pub_packet->var_header.publish.topic_name;
    // convert mqtt msg to nng pub msg
    nng_msg *new_msg;
    uint32_t plen = 0, tlen = 0;
    nng_msg_alloc(&new_msg, 0);
    char *payload = work->pub_packet->payload.data;
    plen = work->pub_packet->payload.len;
    char *tmp_topic = work->pub_packet->var_header.publish.topic_name.body;
    tlen = work->pub_packet->var_header.publish.topic_name.len;
    nng_msg_append(new_msg, tmp_topic, tlen);
    nng_msg_append(new_msg, "/", 1);
    nng_msg_append(new_msg, payload, plen);
	for (size_t t = 0; t < work->config->nng_proxy.pub_count; t++) {
        // iterate all pub node
		conf_nng_pub_node *node = work->config->nng_proxy.pnodes[t];
        for (size_t i = 0; i < node->forwards_count; i++) {
            // topic->body = work->pub_packet->var_header.publish.topic_name.body;
            // topic->len  = work->pub_packet->var_header.publish.topic_name.len;
            log_debug("local topic %s msg topic %s", node->pub_list[i]->local_topic, sub_topic->body);
            if (!topic_filter(node->pub_list[i]->local_topic, (const char *)sub_topic->body)) 
                continue;
            if (work->proto == PROTO_NNG_BRIDGE) {
                // TODO pass nng sub msg directly
                nng_msg_clone(nmsg);
                nng_sendmsg(node->pub_sock, nmsg, NNG_FLAG_NONBLOCK);
            } else {
                nng_msg_clone(new_msg);
                // nng_aio_set_msg(work->aio, new_msg);
                work->state = SEND;
                // NNG sub wont block aio, so we can send them one by one
                // nng_sock_send(node->pub_sock, node->send_aio);
                nng_sendmsg(node->pub_sock, new_msg, NNG_FLAG_NONBLOCK);
            }
        }
    }
    nng_msg_free(new_msg);
}