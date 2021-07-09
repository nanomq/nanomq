//
// Copyright 2020 NanoMQ Team, Inc. <jaylin@emqx.io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdio.h>
#include <string.h>

#include <include/nanomq.h>
#include <mqtt_db.h>
#include <nng.h>
#include <protocol/mqtt/mqtt_parser.h>
#include <zmalloc.h>

#include "include/pub_handler.h"
#include "include/sub_handler.h"

#define ENABLE_RETAIN 1
#define SUPPORT_MQTT5_0 1

static char *bytes_to_str(const unsigned char *src, char *dest, int src_len);
static void  print_hex(
     const char *prefix, const unsigned char *src, int src_len);
static uint32_t append_bytes_with_type(
    nng_msg *msg, uint8_t type, uint8_t *content, uint32_t len);
static void handle_pub_retain(const nano_work *work, char *topic);

void
init_pipe_content(struct pipe_content *pipe_ct)
{
	debug_msg("pub_handler: init pipe_info");
	pipe_ct->pipe_info     = NULL;
	pipe_ct->total         = 0;
	pipe_ct->current_index = 0;
	pipe_ct->encode_msg    = encode_pub_message;
}

void
put_pipe_msgs(client_ctx *sub_ctx, nano_work *self_work,
    struct pipe_content *pipe_ct, mqtt_control_packet_types cmd)
{
	pipe_ct->pipe_info = (struct pipe_info *) zrealloc(pipe_ct->pipe_info,
	    sizeof(struct pipe_info) * (pipe_ct->total + 1));

	pipe_ct->pipe_info[pipe_ct->total].index = pipe_ct->total;
	if (PUBLISH == cmd && sub_ctx != NULL) {
		pipe_ct->pipe_info[pipe_ct->total].pipe = sub_ctx->pid.id;
		pipe_ct->pipe_info[pipe_ct->total].qos =
		    sub_ctx->sub_pkt->node->it->qos;
	} else {
		pipe_ct->pipe_info[pipe_ct->total].pipe = self_work->pid.id;
		pipe_ct->pipe_info[pipe_ct->total].qos =
		    self_work->pub_packet->fixed_header.qos;
	}
	pipe_ct->pipe_info[pipe_ct->total].cmd  = cmd;
	pipe_ct->pipe_info[pipe_ct->total].work = self_work;

	/*	debug_msg("put sub pipe_info: index: [%d], "
	                  "pipe: [%d], "
	                  "qos: [%d], "
	                  "cmd: [%d], "
	                  "self_work: [%p], "
	                  "self pipe: [%d]",
	                  pipe_ct->pipe_info[pipe_ct->total].index,
	                  pipe_ct->pipe_info[pipe_ct->total].pipe,
	                  pipe_ct->pipe_info[pipe_ct->total].qos,
	                  pipe_ct->pipe_info[pipe_ct->total].cmd,
	                  pipe_ct->pipe_info[pipe_ct->total].work,
	                  pipe_ct->pipe_info[pipe_ct->total].work->pid.id
	        );*/

	pipe_ct->total += 1;
}

void
foreach_client(
    void **cli_ctx_list, nano_work *pub_work, struct pipe_content *pipe_ct)
{
	bool               equal = false;
	packet_subscribe * sub_pkt;
	struct client_ctx *ctx;

	for (int i = 0; i < cvector_size(cli_ctx_list); i++) {
		equal   = false;
		ctx     = (struct client_ctx *) cli_ctx_list[i];
		sub_pkt = ctx->sub_pkt;
		// NO LOCAL

		debug_msg("sub pkt %p", sub_pkt);
		debug_msg("pid1 %d", ctx->pid.id);
		debug_msg("pid2 %d", pub_work->pid.id);
		if (sub_pkt->node->it->no_local &&
		    ctx->pid.id == pub_work->pid.id) {
			equal = true;
		}

		if (equal == false) {
			// debug_msg("sub_client: [%p], id: [%s], pipe: [%d]",
			// sub_client, sub_client->id, ctx->pid.id);
			put_pipe_msgs(ctx, pub_work, pipe_ct, PUBLISH);
		}
	}
}

void
handle_pub(nano_work *work, struct pipe_content *pipe_ct)
{
	char **topic_queue = NULL;

	work->pub_packet = (struct pub_packet_struct *) nng_alloc(
	    sizeof(struct pub_packet_struct));

	reason_code result = decode_pub_message(work);
	if (SUCCESS == result) {
		debug_msg("decode message success");

		switch (work->pub_packet->fixed_header.packet_type) {
		case PUBLISH:
			debug_msg("handling PUBLISH (qos %d)",
			    work->pub_packet->fixed_header.qos);

			switch (work->pub_packet->fixed_header.qos) {
			case 0:
				break;
			case 1:
				// put_pipe_msgs(NULL, work, pipe_ct, PUBACK);
				break;
			case 2:
				// put_pipe_msgs(NULL, work, pipe_ct, PUBREC);
				break;
			default:
				debug_msg("invalid qos: %d",
				    work->pub_packet->fixed_header.qos);
				break;
			}

			void **cli_ctx_list = search_client(work->db,
			    work->pub_packet->variable_header.publish
			        .topic_name.body);

			if (cli_ctx_list != NULL) {
				foreach_client(cli_ctx_list, work, pipe_ct);
			}

			cvector_free(cli_ctx_list);

			debug_msg("pipe_info size: [%d]", pipe_ct->total);

#if ENABLE_RETAIN
			handle_pub_retain(work,
			    work->pub_packet->variable_header.publish
			        .topic_name.body);
#endif

			break;

		case PUBACK:
			debug_msg("handling PUBACK");
			// TODO
			break;

		case PUBREC:
			debug_msg("handling PUBREC");
			// put_pipe_msgs(NULL, work, pipe_ct, PUBREL);
			break;

		case PUBREL:
			debug_msg("handling PUBREL");
			// put_pipe_msgs(NULL, work, pipe_ct, PUBCOMP);
			break;

		case PUBCOMP:
			debug_msg("handling PUBCOMP");
			// TODO
			break;

		default:
			break;
		}
	} else {
		debug_msg("decode message failed: %d", result);
		// TODO send DISCONNECT with reason_code if MQTT Version=5.0
	}
}

#if ENABLE_RETAIN
static void
handle_pub_retain(const nano_work *work, char *topic)
{
	struct retain_msg *retain = NULL;

	if (work->pub_packet->fixed_header.retain) {
		retain_msg *r = NULL;

		if (work->pub_packet->payload_body.payload_len > 0) {
			retain      = nng_alloc(sizeof(struct retain_msg));
			retain->qos = work->pub_packet->fixed_header.qos;
			nng_msg_clone(work->msg);

			retain->message = work->msg;
			retain->exist   = true;
			retain->m       = NULL;
			debug_msg("update/add retain message");
			debug("found retain [%p], message: [%p][%p]\n", retain,
			    retain->message,
			    nng_msg_payload_ptr(retain->message));
			r = search_insert_retain(work->db_ret, topic, retain);
		} else {
			debug_msg("delete retain message");
			r = search_delete_retain(work->db_ret, topic);
		}
		retain_msg *ret = (retain_msg *) r;

		if (ret != NULL) {
			if (ret->message) {
				nng_msg_free(ret->message);
			}
			nng_free(ret, sizeof(struct retain_msg));
			ret = NULL;
		}
	}
}
#endif

struct pub_packet_struct *
copy_pub_packet(struct pub_packet_struct *src_pub_packet)
{
	struct pub_packet_struct *packet =
	    nng_alloc(sizeof(struct pub_packet_struct));
	packet->variable_header.publish.topic_name.body = nng_alloc(
	    src_pub_packet->variable_header.publish.topic_name.len + 1);
	memset(packet->variable_header.publish.topic_name.body, 0,
	    src_pub_packet->variable_header.publish.topic_name.len + 1);
	memcpy(packet->variable_header.publish.topic_name.body,
	    src_pub_packet->variable_header.publish.topic_name.body,
	    src_pub_packet->variable_header.publish.topic_name.len);
	packet->variable_header.publish.topic_name.len =
	    src_pub_packet->variable_header.publish.topic_name.len;

	packet->payload_body.payload =
	    nng_alloc(src_pub_packet->payload_body.payload_len + 1);
	memset(packet->payload_body.payload, 0,
	    src_pub_packet->payload_body.payload_len + 1);
	memcpy(packet->payload_body.payload,
	    src_pub_packet->payload_body.payload,
	    src_pub_packet->payload_body.payload_len);
	packet->payload_body.payload_len =
	    src_pub_packet->payload_body.payload_len;
	return packet;
}

void
free_pub_packet(struct pub_packet_struct *pub_packet)
{
	if (pub_packet != NULL) {
		if (pub_packet->fixed_header.packet_type == PUBLISH) {
			if (pub_packet->variable_header.publish.topic_name
			            .body != NULL &&
			    pub_packet->variable_header.publish.topic_name
			            .len > 0) {
				nng_free(pub_packet->variable_header.publish
				             .topic_name.body,
				    pub_packet->variable_header.publish
				            .topic_name.len +
				        1);
				pub_packet->variable_header.publish.topic_name
				    .body = NULL;
				pub_packet->variable_header.publish.topic_name
				    .len = 0;
				debug_msg("free memory topic");
			}

			if (pub_packet->payload_body.payload != NULL &&
			    pub_packet->payload_body.payload_len > 0) {
				nng_free(pub_packet->payload_body.payload,
				    pub_packet->payload_body.payload_len + 1);
				pub_packet->payload_body.payload     = NULL;
				pub_packet->payload_body.payload_len = 0;
				debug_msg("free memory payload");
			}
		}

		nng_free(pub_packet, sizeof(struct pub_packet_struct));
		pub_packet = NULL;
		debug_msg("free pub_packet");
	}
}

void
free_pipes_info(struct pipe_info *p_info)
{
	if (p_info != NULL) {
		zfree(p_info);
		p_info = NULL;
		debug_msg("free pipes_info");
	}
}

static uint32_t
append_bytes_with_type(
    nng_msg *msg, uint8_t type, uint8_t *content, uint32_t len)
{
	if (len > 0) {
		nng_msg_append(msg, &type, 1);
		nng_msg_append_u16(msg, len);
		nng_msg_append(msg, content, len);
		return 0;
	}

	return 1;
}

bool
encode_pub_message(nng_msg *dest_msg, const nano_work *work,
    mqtt_control_packet_types cmd, uint8_t sub_qos, bool dup)
{
	uint8_t  tmp[4]     = { 0 };
	uint32_t arr_len    = 0;
	int      append_res = 0;

	properties_type prop_type;

	debug_msg("start encode message");

	nng_msg_clear(dest_msg);
	nng_msg_header_clear(dest_msg);
	nng_msg_set_cmd_type(dest_msg, CMD_UNKNOWN);
	switch (cmd) {
	case PUBLISH:
		/*fixed header*/
		nng_msg_set_cmd_type(dest_msg, CMD_PUBLISH);
		work->pub_packet->fixed_header.packet_type = cmd;
		// work->pub_packet->fixed_header.qos =
		// work->pub_packet->fixed_header.qos < sub_qos ?
		// work->pub_packet->fixed_header.qos : sub_qos;
		work->pub_packet->fixed_header.dup = dup;
		append_res                         = nng_msg_header_append(
                    dest_msg, (uint8_t *) &work->pub_packet->fixed_header, 1);

		arr_len = put_var_integer(
		    tmp, work->pub_packet->fixed_header.remain_len);

		append_res = nng_msg_header_append(dest_msg, tmp, arr_len);
		nng_msg_set_remaining_len(
		    dest_msg, work->pub_packet->fixed_header.remain_len);
		debug_msg("header len [%ld] remain len [%d]",
		    nng_msg_header_len(dest_msg),
		    work->pub_packet->fixed_header.remain_len);

		/*variable header*/
		// topic name
		if (work->pub_packet->variable_header.publish.topic_name.len >
		    0) {
			append_res = nng_msg_append_u16(dest_msg,
			    work->pub_packet->variable_header.publish
			        .topic_name.len);

			append_res = nng_msg_append(dest_msg,
			    work->pub_packet->variable_header.publish
			        .topic_name.body,
			    work->pub_packet->variable_header.publish
			        .topic_name.len);
		}

		// identifier
		if (work->pub_packet->fixed_header.qos > 0) {
			append_res = nng_msg_append_u16(dest_msg,
			    work->pub_packet->variable_header.publish
			        .packet_identifier);
		}
		debug_msg("after topic and id len in msg already [%ld]",
		    nng_msg_len(dest_msg));

#if SUPPORT_MQTT5_0
		if (PROTOCOL_VERSION_v5 == work->proto) {
			// properties
			// properties length
			memset(tmp, 0, sizeof(tmp));
			arr_len = put_var_integer(tmp,
			    work->pub_packet->variable_header.publish
			        .properties.len);
			nng_msg_append(dest_msg, tmp, arr_len);
			debug_msg("arr_len [%d]", arr_len);

			// Payload Format Indicator
			if (work->pub_packet->variable_header.publish
			        .properties.content.publish
			        .payload_fmt_indicator.has_value) {
				prop_type = PAYLOAD_FORMAT_INDICATOR;
				nng_msg_append(dest_msg, &prop_type, 1);
				nng_msg_append(dest_msg,
				    &work->pub_packet->variable_header.publish
				         .properties.content.publish
				         .payload_fmt_indicator.value,
				    sizeof(
				        work->pub_packet->variable_header
				            .publish.properties.content.publish
				            .payload_fmt_indicator));
			}

			// Message Expiry Interval
			if (work->pub_packet->variable_header.publish
			        .properties.content.publish.msg_expiry_interval
			        .has_value) {
				prop_type = MESSAGE_EXPIRY_INTERVAL;
				nng_msg_append(dest_msg, &prop_type, 1);
				nng_msg_append_u32(dest_msg,
				    work->pub_packet->variable_header.publish
				        .properties.content.publish
				        .msg_expiry_interval.value);
			}

			// Topic Alias
			if (work->pub_packet->variable_header.publish
			        .properties.content.publish.topic_alias
			        .has_value) {
				prop_type = TOPIC_ALIAS;
				nng_msg_append(dest_msg, &prop_type, 1);
				nng_msg_append_u16(dest_msg,
				    work->pub_packet->variable_header.publish
				        .properties.content.publish.topic_alias
				        .value);
			}

			// Response Topic
			if (work->pub_packet->variable_header.publish
			        .properties.content.publish.response_topic
			        .len > 0) {
				append_bytes_with_type(dest_msg,
				    RESPONSE_TOPIC,
				    (uint8_t *) work->pub_packet
				        ->variable_header.publish.properties
				        .content.publish.response_topic.body,
				    work->pub_packet->variable_header.publish
				        .properties.content.publish
				        .response_topic.len);
			}

			// Correlation Data
			if (work->pub_packet->variable_header.publish
			        .properties.content.publish.correlation_data
			        .len > 0) {
				append_bytes_with_type(dest_msg,
				    CORRELATION_DATA,
				    work->pub_packet->variable_header.publish
				        .properties.content.publish
				        .correlation_data.body,
				    work->pub_packet->variable_header.publish
				        .properties.content.publish
				        .correlation_data.len);
			}

			// User Property
			if (work->pub_packet->variable_header.publish
			        .properties.content.publish.user_property
			        .len_key > 0) {
				append_bytes_with_type(dest_msg, USER_PROPERTY,
				    (uint8_t *) work->pub_packet
				        ->variable_header.publish.properties
				        .content.publish.user_property.key,
				    work->pub_packet->variable_header.publish
				        .properties.content.publish
				        .user_property.len_key);
				nng_msg_append(dest_msg,
				    (uint8_t *) work->pub_packet
				        ->variable_header.publish.properties
				        .content.publish.user_property.val,
				    work->pub_packet->variable_header.publish
				        .properties.content.publish
				        .user_property.len_val);
			}

			// Subscription Identifier
			if (work->pub_packet->variable_header.publish
			        .properties.content.publish
			        .subscription_identifier.has_value) {
				prop_type = SUBSCRIPTION_IDENTIFIER;
				nng_msg_append(dest_msg, &prop_type, 1);
				memset(tmp, 0, sizeof(tmp));
				arr_len = put_var_integer(tmp,
				    work->pub_packet->variable_header.publish
				        .properties.content.publish
				        .subscription_identifier.value);
				nng_msg_append(dest_msg, tmp, arr_len);
			}

			// CONTENT TYPE
			if (work->pub_packet->variable_header.publish
			        .properties.content.publish.content_type.len >
			    0) {
				append_bytes_with_type(dest_msg, CONTENT_TYPE,
				    (uint8_t *) work->pub_packet
				        ->variable_header.publish.properties
				        .content.publish.content_type.body,
				    work->pub_packet->variable_header.publish
				        .properties.content.publish
				        .content_type.len);
			}
		}
		/* check */
		else {
			debug_msg("pro_ver [%d]", work->proto);
		}
#endif
		debug_msg("property len in msg already [%ld]",
		    nng_msg_len(dest_msg));

		// payload
		if (work->pub_packet->payload_body.payload_len > 0) {
			// nng_msg_set_payload_ptr(msg, nng_msg_body());
			append_res = nng_msg_append(dest_msg,
			    work->pub_packet->payload_body.payload,
			    work->pub_packet->payload_body.payload_len);
			//				debug_msg("payload [%s]
			//len
			//[%d]", (char
			//*)work->pub_packet->payload_body.payload,
			// work->pub_packet->payload_body.payload_len);
		}

		debug_msg("after payload len in msg already [%ld]",
		    nng_msg_len(dest_msg));
		break;

	case PUBREL:
		nng_msg_set_cmd_type(dest_msg, CMD_PUBREL);
	case PUBACK:
		nng_msg_set_cmd_type(dest_msg, CMD_PUBACK);
	case PUBREC:
		nng_msg_set_cmd_type(dest_msg, CMD_PUBREC);
	case PUBCOMP:
		debug_msg("encode %d message", cmd);
		nng_msg_set_cmd_type(dest_msg, CMD_PUBCOMP);
		struct pub_packet_struct pub_response = {
			.fixed_header.packet_type = cmd,
			.fixed_header.dup         = dup,
			.fixed_header.qos         = 0,
			.fixed_header.retain      = 0,
			.fixed_header.remain_len  = 2, // TODO
			.variable_header.pub_arrc.packet_identifier =
			    work->pub_packet->variable_header.publish
			        .packet_identifier
		};

		/*fixed header*/
		nng_msg_header_append(
		    dest_msg, (uint8_t *) &pub_response.fixed_header, 1);
		arr_len =
		    put_var_integer(tmp, pub_response.fixed_header.remain_len);
		nng_msg_header_append(dest_msg, tmp, arr_len);

		/*variable header*/
		// identifier
		nng_msg_append_u16(dest_msg,
		    pub_response.variable_header.pub_arrc.packet_identifier);

		// reason code
		if (pub_response.fixed_header.remain_len > 2) {
			uint8_t reason_code =
			    pub_response.variable_header.pub_arrc.reason_code;
			nng_msg_append(dest_msg, (uint8_t *) &reason_code,
			    sizeof(reason_code));

#if SUPPORT_MQTT5_0
			if (PROTOCOL_VERSION_v5 == work->proto) {
				// properties
				if (pub_response.fixed_header.remain_len >=
				    4) {

					memset(tmp, 0, sizeof(tmp));
					arr_len = put_var_integer(tmp,
					    pub_response.variable_header
					        .pub_arrc.properties.len);
					nng_msg_append(dest_msg, tmp, arr_len);

					// reason string
					append_bytes_with_type(dest_msg,
					    REASON_STRING,
					    (uint8_t *) pub_response
					        .variable_header.pub_arrc
					        .properties.content.pub_arrc
					        .reason_string.body,
					    pub_response.variable_header
					        .pub_arrc.properties.content
					        .pub_arrc.reason_string.len);

					// user properties
					append_bytes_with_type(dest_msg,
					    USER_PROPERTY,
					    (uint8_t *) pub_response
					        .variable_header.pub_arrc
					        .properties.content.pub_arrc
					        .user_property.key,
					    pub_response.variable_header
					        .pub_arrc.properties.content
					        .pub_arrc.user_property
					        .len_key);
					nng_msg_append(dest_msg,
					    (uint8_t *) pub_response
					        .variable_header.pub_arrc
					        .properties.content.pub_arrc
					        .user_property.val,
					    pub_response.variable_header
					        .pub_arrc.properties.content
					        .pub_arrc.user_property
					        .len_val);
				}
			}
#endif
		}
		break;
	default:
		break;
	}

	debug_msg("end encode message");
	return true;
}

reason_code
decode_pub_message(nano_work *work)
{
	int     pos      = 0;
	int     used_pos = 0;
	int     len, len_of_varint;
	uint8_t proto_ver = conn_param_get_protover(work->cparam);
	if (nng_msg_cmd_type(work->msg) == CMD_PUBLISH) {
		proto_ver = 4;
	}
	work->proto       = proto_ver;

	nng_msg *                 msg        = work->msg;
	struct pub_packet_struct *pub_packet = work->pub_packet;

	uint8_t *msg_body = nng_msg_body(msg);
	size_t   msg_len  = nng_msg_len(msg);

	pub_packet->fixed_header =
	    *(struct fixed_header *) nng_msg_header(msg);
	pub_packet->fixed_header.remain_len = nng_msg_remaining_len(msg);

	debug_msg(
	    "cmd: %d, retain: %d, qos: %d, dup: %d, remaining length: %d",
	    pub_packet->fixed_header.packet_type,
	    pub_packet->fixed_header.retain, pub_packet->fixed_header.qos,
	    pub_packet->fixed_header.dup, pub_packet->fixed_header.remain_len);

	if (pub_packet->fixed_header.remain_len > msg_len) {
		debug_msg("ERROR: remainlen > msg_len");
		return PROTOCOL_ERROR;
	}

	switch (pub_packet->fixed_header.packet_type) {
	case PUBLISH:
		// variable header
		// topic length
		NNI_GET16(msg_body + pos,
		    pub_packet->variable_header.publish.topic_name.len);
		pub_packet->variable_header.publish.topic_name.body =
		    copy_utf8_str(msg_body, &pos, &len);

		if (pub_packet->variable_header.publish.topic_name.len > 0) {
			if (strchr(pub_packet->variable_header.publish
			               .topic_name.body,
			        '+') != NULL ||
			    strchr(pub_packet->variable_header.publish
			               .topic_name.body,
			        '#') != NULL) {

				// TODO search topic alias if mqtt version
				// = 5.0

				// protocol error
				debug_msg(
				    "protocol error in topic:[%s], len: [%d]",
				    pub_packet->variable_header.publish
				        .topic_name.body,
				    pub_packet->variable_header.publish
				        .topic_name.len);

				return PROTOCOL_ERROR;
			}
		}

		debug_msg("topic: [%s]",
		    pub_packet->variable_header.publish.topic_name.body);

		if (pub_packet->fixed_header.qos >
		    0) { // extract packet_identifier while qos > 0
			NNI_GET16(msg_body + pos,
			    pub_packet->variable_header.publish
			        .packet_identifier);
			debug_msg("identifier: [%d]",
			    pub_packet->variable_header.publish
			        .packet_identifier);
			pos += 2;
		}

		used_pos                                           = pos;
		pub_packet->variable_header.publish.properties.len = 0;

#if SUPPORT_MQTT5_0
		if (PROTOCOL_VERSION_v5 == proto_ver) {
			len_of_varint = 0;
			pub_packet->variable_header.publish.properties.len =
			    get_var_integer(msg_body, &len_of_varint);
			pos += len_of_varint;
			debug_msg("property len [%d]",
			    pub_packet->variable_header.publish.properties
			        .len);
			init_pub_packet_property(pub_packet);
			if (pub_packet->variable_header.publish.properties
			        .len > 0) {
				for (uint32_t i = 0;
				     i < pub_packet->variable_header.publish
				             .properties.len;) {
					properties_type prop_type =
					    get_var_integer(msg_body, &pos);
					// TODO the same property cannot appear
					// twice
					switch (prop_type) {
					case PAYLOAD_FORMAT_INDICATOR:
						if (pub_packet->variable_header
						        .publish.properties
						        .content.publish
						        .payload_fmt_indicator
						        .has_value == false) {
							pub_packet
							    ->variable_header
							    .publish.properties
							    .content.publish
							    .payload_fmt_indicator
							    .value =
							    *(msg_body + pos);
							pub_packet
							    ->variable_header
							    .publish.properties
							    .content.publish
							    .payload_fmt_indicator
							    .has_value = true;
							++pos;
							++i;
						}
						break;

					case MESSAGE_EXPIRY_INTERVAL:
						if (pub_packet->variable_header
						        .publish.properties
						        .content.publish
						        .msg_expiry_interval
						        .has_value == false) {
							NNI_GET32(
							    msg_body + pos,
							    pub_packet
							        ->variable_header
							        .publish
							        .properties
							        .content
							        .publish
							        .msg_expiry_interval
							        .value);
							pub_packet
							    ->variable_header
							    .publish.properties
							    .content.publish
							    .msg_expiry_interval
							    .has_value = true;
							pos += 4;
							i += 4;
						}
						break;

					case CONTENT_TYPE:
						if (pub_packet->variable_header
						        .publish.properties
						        .content.publish
						        .content_type.len ==
						    0) {
							pub_packet
							    ->variable_header
							    .publish.properties
							    .content.publish
							    .content_type
							    .len = get_utf8_str(
							    &pub_packet
							         ->variable_header
							         .publish
							         .properties
							         .content
							         .publish
							         .content_type
							         .body,
							    msg_body, &pos);
							i = i +
							    pub_packet
							        ->variable_header
							        .publish
							        .properties
							        .content
							        .publish
							        .content_type
							        .len +
							    2;
						}
						break;

					case TOPIC_ALIAS:
						if (pub_packet->variable_header
						        .publish.properties
						        .content.publish
						        .topic_alias
						        .has_value == false) {
							NNI_GET16(
							    msg_body + pos,
							    pub_packet
							        ->variable_header
							        .publish
							        .properties
							        .content
							        .publish
							        .topic_alias
							        .value);
							pub_packet
							    ->variable_header
							    .publish.properties
							    .content.publish
							    .topic_alias
							    .has_value = true;
							pos += 2;
							i += 2;
						}
						break;

					case RESPONSE_TOPIC:
						if (pub_packet->variable_header
						        .publish.properties
						        .content.publish
						        .response_topic.len ==
						    0) {
							pub_packet
							    ->variable_header
							    .publish.properties
							    .content.publish
							    .response_topic
							    .len = get_utf8_str(
							    &pub_packet
							         ->variable_header
							         .publish
							         .properties
							         .content
							         .publish
							         .response_topic
							         .body,
							    msg_body, &pos);
							i = i +
							    pub_packet
							        ->variable_header
							        .publish
							        .properties
							        .content
							        .publish
							        .content_type
							        .len +
							    2;
						}
						break;

					case CORRELATION_DATA:
						if (pub_packet->variable_header
						        .publish.properties
						        .content.publish
						        .correlation_data
						        .len == 0) {
							pub_packet
							    ->variable_header
							    .publish.properties
							    .content.publish
							    .correlation_data
							    .len =
							    get_variable_binary(
							        &pub_packet
							             ->variable_header
							             .publish
							             .properties
							             .content
							             .publish
							             .correlation_data
							             .body,
							        msg_body +
							            pos);
							pos +=
							    pub_packet
							        ->variable_header
							        .publish
							        .properties
							        .content
							        .publish
							        .correlation_data
							        .len +
							    2;
							i +=
							    pub_packet
							        ->variable_header
							        .publish
							        .properties
							        .content
							        .publish
							        .correlation_data
							        .len +
							    2;
						}
						break;

					case USER_PROPERTY:
						if (pub_packet->variable_header
						        .publish.properties
						        .content.publish
						        .user_property
						        .len_key == 0) {
							pub_packet
							    ->variable_header
							    .publish.properties
							    .content.publish
							    .user_property
							    .len_key = get_utf8_str(
							    &pub_packet
							         ->variable_header
							         .publish
							         .properties
							         .content
							         .publish
							         .user_property
							         .key,
							    msg_body, &pos);
							i +=
							    pub_packet
							        ->variable_header
							        .publish
							        .properties
							        .content
							        .publish
							        .user_property
							        .len_key +
							    2;
							pub_packet
							    ->variable_header
							    .publish.properties
							    .content.publish
							    .user_property
							    .len_val = get_utf8_str(
							    &pub_packet
							         ->variable_header
							         .publish
							         .properties
							         .content
							         .publish
							         .user_property
							         .val,
							    msg_body, &pos);
							i +=
							    pub_packet
							        ->variable_header
							        .publish
							        .properties
							        .content
							        .publish
							        .user_property
							        .len_val +
							    2;
						}
						break;

					case SUBSCRIPTION_IDENTIFIER:
						if (pub_packet->variable_header
						        .publish.properties
						        .content.publish
						        .subscription_identifier
						        .has_value == false) {
							len_of_varint = 0;
							pub_packet
							    ->variable_header
							    .publish.properties
							    .content.publish
							    .subscription_identifier
							    .value =
							    get_var_integer(
							        msg_body,
							        &len_of_varint);
							i += len_of_varint;
							pub_packet
							    ->variable_header
							    .publish.properties
							    .content.publish
							    .subscription_identifier
							    .has_value = true;
							// Protocol error while
							// Subscription
							// Identifier = 0
							if (pub_packet
							        ->variable_header
							        .publish
							        .properties
							        .content
							        .publish
							        .subscription_identifier
							        .value == 0) {
								return false;
							}
						}
						break;

					default:
						i++;
						break;
					}
				}
			}
			used_pos += pub_packet->variable_header.publish
			                .properties.len +
			    1;
		}
		/* check */
		else {
			debug_msg("NOMQTT5ERR [%d] [%d]", proto_ver,
			    PROTOCOL_VERSION_v5);
		}
#endif

		debug_msg("used pos: [%d]", used_pos);
		// payload
		pub_packet->payload_body.payload_len =
		    (uint32_t)(msg_len - (size_t) used_pos);

		if (pub_packet->payload_body.payload_len > 0) {
			pub_packet->payload_body.payload = nng_alloc(
			    pub_packet->payload_body.payload_len + 1);
			memset(pub_packet->payload_body.payload, 0,
			    pub_packet->payload_body.payload_len + 1);
			memcpy(pub_packet->payload_body.payload,
			    (uint8_t *) (msg_body + pos),
			    pub_packet->payload_body.payload_len);
			debug_msg("payload: [%s], len = %u",
			    pub_packet->payload_body.payload,
			    pub_packet->payload_body.payload_len);
		}
		break;

	case PUBACK:
	case PUBREC:
	case PUBREL:
	case PUBCOMP:
		NNI_GET16(msg_body + pos,
		    pub_packet->variable_header.pub_arrc.packet_identifier);
		pos += 2;
		if (pub_packet->fixed_header.remain_len == 2) {
			// Reason code can be ignored when remaining length = 2
			// and reason code = 0x00(Success)
			pub_packet->variable_header.pub_arrc.reason_code =
			    SUCCESS;
			break;
		}
		pub_packet->variable_header.pub_arrc.reason_code =
		    *(msg_body + pos);
		++pos;
#if SUPPORT_MQTT5_0
		if (pub_packet->fixed_header.remain_len > 4) {
			pub_packet->variable_header.pub_arrc.properties.len =
			    get_var_integer(msg_body, &pos);
			for (uint32_t i = 0;
			     i < pub_packet->variable_header.pub_arrc
			             .properties.len;) {
				properties_type prop_type =
				    get_var_integer(msg_body, &pos);
				switch (prop_type) {
				case REASON_STRING:
					pub_packet->variable_header.pub_arrc
					    .properties.content.pub_arrc
					    .reason_string.len = get_utf8_str(
					    &pub_packet->variable_header
					         .pub_arrc.properties.content
					         .pub_arrc.reason_string.body,
					    msg_body, &pos);
					i += pub_packet->variable_header
					         .pub_arrc.properties.content
					         .pub_arrc.reason_string.len +
					    2;
					break;

				case USER_PROPERTY:
					if (pub_packet->variable_header
					        .pub_arrc.properties.content
					        .pub_arrc.user_property
					        .len_key != 0) {
						pub_packet->variable_header
						    .pub_arrc.properties
						    .content.pub_arrc
						    .user_property
						    .len_key = get_utf8_str(
						    &pub_packet
						         ->variable_header
						         .pub_arrc.properties
						         .content.pub_arrc
						         .user_property.key,
						    msg_body, &pos);
						i +=
						    pub_packet->variable_header
						        .pub_arrc.properties
						        .content.pub_arrc
						        .user_property
						        .len_key +
						    2;
						pub_packet->variable_header
						    .pub_arrc.properties
						    .content.pub_arrc
						    .user_property
						    .len_val = get_utf8_str(
						    &pub_packet
						         ->variable_header
						         .pub_arrc.properties
						         .content.pub_arrc
						         .user_property.val,
						    msg_body, &pos);
						i +=
						    pub_packet->variable_header
						        .pub_arrc.properties
						        .content.pub_arrc
						        .user_property
						        .len_val +
						    2;
					}
					break;

				default:
					i++;
					break;
				}
			}
		}
#endif
		break;

	default:
		break;
	}
	return SUCCESS;
}

/**
 * byte array to hex string
 *
 * @param src
 * @param dest
 * @param src_len
 * @return
 */
static char *
bytes_to_str(const unsigned char *src, char *dest, int src_len)
{
	int  i;
	char szTmp[3] = { 0 };

	for (i = 0; i < src_len; i++) {
		sprintf(szTmp, "%02X", (unsigned char) src[i]);
		memcpy(dest + i * 2, szTmp, 2);
	}
	return dest;
}

static void
print_hex(const char *prefix, const unsigned char *src, int src_len)
{
	if (src_len > 0) {
		char *dest = (char *) nng_alloc(src_len * 2);

		if (dest == NULL) {
			debug_msg("alloc fail!");
			return;
		}
		dest = bytes_to_str(src, dest, src_len);

		debug_msg("%s%s", prefix, dest);

		nng_free(dest, src_len * 2);
	}
}

void
init_pub_packet_property(struct pub_packet_struct *pub_packet)
{
	pub_packet->variable_header.publish.properties.content.publish
	    .payload_fmt_indicator.has_value = false;
	pub_packet->variable_header.publish.properties.content.publish
	    .msg_expiry_interval.has_value = false;
	pub_packet->variable_header.publish.properties.content.publish
	    .response_topic.len = 0;
	pub_packet->variable_header.publish.properties.content.publish
	    .topic_alias.has_value = 0;
	pub_packet->variable_header.publish.properties.content.publish
	    .content_type.len = 0;
	pub_packet->variable_header.publish.properties.content.publish
	    .correlation_data.len = 0;
	pub_packet->variable_header.publish.properties.content.publish
	    .user_property.len_key = 0;
	pub_packet->variable_header.publish.properties.content.publish
	    .user_property.len_val = 0;
	pub_packet->variable_header.publish.properties.content.publish
	    .subscription_identifier.has_value = false;
}
