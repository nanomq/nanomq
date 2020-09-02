/**
  * Created by Alvin on 2020/7/25.
  */


#include <stdio.h>
#include <string.h>

#include <nng.h>
#include <mqtt_db.h>
#include <protocol/mqtt/mqtt_parser.h>
#include <include/nanomq.h>
#include <zmalloc.h>
#include <malloc.h>

#include "include/pub_handler.h"
#include "include/subscribe_handle.h"

#define SUPPORT_MQTT5_0 1

static void handle_client_pipe_msgs(struct client *sub_client, void **pipe_content, uint32_t *total, void *pub_pucket);
static void handle_client_pipes(struct client *sub_client, void **pipe_content, uint32_t *total, void *packet);

static char *bytes_to_str(const unsigned char *src, char *dest, int src_len);
static void print_hex(const char *prefix, const unsigned char *src, int src_len);
static uint32_t append_bytes_with_type(nng_msg *msg, uint8_t type, uint8_t *content, uint32_t len);


static void handle_client_pipe_msgs(struct client *sub_client, void **pipe_content, uint32_t *total, void *pub_pucket)
{

	nng_msg *msg;
	nng_msg_alloc(&msg, 0);

	emq_work                 *client_work  = (emq_work *) sub_client->ctxt;
	uint32_t                 current_index = *total;
	struct pub_packet_struct *pub_pk       = (struct pub_packet_struct *) pub_pucket;
	*pipe_content = (struct pipe_nng_msg *) realloc(*pipe_content,
	                                                sizeof(struct pipe_nng_msg) * (current_index + 2));
	debug_msg("realloc for pipe_nng_msg: [%p],nmember: [%d], size: [%lu]", *pipe_content, current_index + 2,
	          sizeof(struct pipe_nng_msg) * (current_index + 2));

	struct pipe_nng_msg **pnm = (struct pipe_nng_msg **) pipe_content;

	uint8_t temp_qos = pub_pk->fixed_header.qos;
	pub_pk->fixed_header.qos = pub_pk->fixed_header.qos < client_work->sub_pkt->node->it->qos ?
	                           pub_pk->fixed_header.qos : client_work->sub_pkt->node->it->qos;
	debug_msg("set qos: [%d]", pub_pk->fixed_header.qos);
	encode_pub_message(msg, pub_pk, client_work);

	debug_msg("put pipe content into pipe_nng_msg");

	(*pnm)[current_index].index = current_index;
	(*pnm)[current_index].pipe  = client_work->pid.id;
	(*pnm)[current_index].qos   = pub_pk->fixed_header.qos;
	(*pnm)[current_index].msg   = msg;

	(*pnm)[current_index + 1].index = 0;
	(*pnm)[current_index + 1].pipe  = 0;
	(*pnm)[current_index + 1].qos   = 0;
	(*pnm)[current_index + 1].msg   = NULL;

	pub_pk->fixed_header.qos = temp_qos;

	*total = current_index + 1;

}

static void handle_client_pipes(struct client *sub_client, void **pipe_content, uint32_t *total, void *packet)
{
	uint32_t current_index = *total;
	uint32_t **pipes       = (uint32_t **) pipe_content;

	emq_work *client_work = (emq_work *) sub_client->ctxt;
	*pipes = realloc(*pipes, sizeof(uint32_t) * (current_index + 2));

	(*pipes)[current_index]     = client_work->pid.id;
	(*pipes)[current_index + 1] = 0;

	debug_msg("get pipe id, sub_pipes[%d]: [%d]", *total, (*pipes)[*total]);

	*total = current_index + 1;
}


void foreach_client(struct clients *sub_clients, void **pipe_content, uint32_t *totals, void *packet,
                    handle_client handle_cb)
{
	int  cols       = 1;
	char **id_queue = NULL;

	while (sub_clients) {
		struct client *sub_client = sub_clients->sub_client;
		while (sub_client) {
			bool equal = false;
			id_queue = (char **) zrealloc(id_queue, cols * sizeof(char *));

			for (int i = 0; i < cols - 1; i++) {
				if (!strcmp(sub_client->id, id_queue[i])) {
					equal = true;
					break;
				}
			}

			if (equal == false) {
				id_queue[cols - 1] = sub_client->id;
				debug_msg("sub_client: [%p], id: [%s]\n", sub_client, sub_client->id);
				handle_cb(sub_client, pipe_content, totals, packet);
				cols++;
			}
			sub_client = sub_client->next;
		}
		sub_clients               = sub_clients->down;
	}
	zfree(id_queue);

}


void handle_pub(emq_work *work, nng_msg *send_msg, void **pipes, transmit_msgs tx_msgs)
{
	char                  **topic_queue = NULL;
	struct topic_and_node *tp_node      = NULL;
	struct client         *sub_client   = NULL;

	uint32_t self_pipe_id[2] = {work->pid.id, 0};
	uint32_t total_sub_pipes;

	bool                  free_packet   = true;

	work->pub_packet = (struct pub_packet_struct *) nng_alloc(sizeof(struct pub_packet_struct));

	reason_code result = decode_pub_message(work);
	if (SUCCESS == result) {
		debug_msg("decode message success");

		struct pub_packet_struct pub_response = {
				.fixed_header.qos = 0,
				.fixed_header.dup = 0,
				.fixed_header.retain = 0,
				.fixed_header.remain_len = 2,
				.variable_header.pub_arrc.packet_identifier = work->pub_packet->variable_header.publish.packet_identifier
		};

		switch (work->pub_packet->fixed_header.packet_type) {
			case PUBLISH:
				debug_msg("handling PUBLISH");
				topic_queue = topic_parse(work->pub_packet->variable_header.publish.topic_name.str_body);

				struct clients *client_list = search_client(work->db->root, topic_queue);

				total_sub_pipes = 0;

				if (client_list != NULL) {
#if DISTRIBUTE_DIFF_MSG
					foreach_client(client_list, pipes, &total_sub_pipes, work->pub_packet, handle_client_pipe_msgs);
#else
					foreach_client(client_list, &pipes, &total_sub_pipes, NULL, handle_client_pipes);
#endif
				}

				debug_msg("pipes: [%p], total_sub_pipes: [%d]", pipes, total_sub_pipes);

				switch (work->pub_packet->fixed_header.qos) {
					case 0:
						work->pub_packet->fixed_header.dup = 0;
						break;
					case 1:
						pub_response.fixed_header.packet_type = PUBACK;
						encode_pub_message(send_msg, &pub_response, work);
						tx_msgs(send_msg, work, self_pipe_id);
						work->pub_packet->fixed_header.dup = 0;//if publish first time
						break;
					case 2:
						pub_response.fixed_header.packet_type = PUBREC;
						encode_pub_message(send_msg, &pub_response, work);
						tx_msgs(send_msg, work, self_pipe_id);
						work->pub_packet->fixed_header.dup = 0;//if publish first time
						break;
					default:
						debug_msg("invalid qos: %d", work->pub_packet->fixed_header.qos);
						break;
				}

				if (work->pub_packet->fixed_header.retain) {
					debug_msg("handle retain message");
					tp_node = nng_alloc(sizeof(struct topic_and_node));
					search_node(work->db, topic_queue, tp_node);

//					struct topic_and_node *temp_tan = tp_node;

					debug_msg("search result, topic_and_node: [%p]", tp_node);

					struct retain_msg *retain = NULL;

					if (tp_node->topic == NULL) {

						retain = get_retain_msg(tp_node->node);
						debug_msg("get retain: [%p]", retain);

						if (retain != NULL) {
							if (retain->message != NULL) {
								nng_free(retain->message, sizeof(struct pub_packet_struct));
								retain->message = NULL;
							}
							nng_free(retain, sizeof(struct retain_msg));
							retain = NULL;
						}
					} else {
						add_node(tp_node, NULL);
					}

					debug_msg("alloc retain ago");
					retain = nng_alloc(sizeof(struct retain_msg));
					debug_msg("alloc retain later: [%p]", retain);

					retain->qos = work->pub_packet->fixed_header.qos;
					if (work->pub_packet->payload_body.payload_len > 0) {
						retain->exist   = true;
						retain->message = work->pub_packet;
						free_packet = false;
					} else {
						retain->exist   = false;
						retain->message = NULL;
					}

//					search_node(work->db, topic_queue, tp_node); //FIXME should remove later
					set_retain_msg(tp_node->node, retain);

					if (tp_node != NULL) {
						nng_free(tp_node, sizeof(struct topic_and_node));
						tp_node = NULL;
						debug_msg("free memory topic_and_node");
					}
				}

#if !DISTRIBUTE_DIFF_MSG
				if (total_sub_pipes > 0) {
					encode_pub_message(send_msg, work->pub_packet, work);
					tx_msgs(send_msg, work, pipes);
				}
#endif

				if (free_packet) {
					if (work->pub_packet->variable_header.publish.topic_name.str_body != NULL) {
						nng_free(work->pub_packet->variable_header.publish.topic_name.str_body,
						         work->pub_packet->variable_header.publish.topic_name.str_len + 1);
						work->pub_packet->variable_header.publish.topic_name.str_body = NULL;
						debug_msg("free memory topic");
					}

					if (work->pub_packet->payload_body.payload != NULL) {
						nng_free(work->pub_packet->payload_body.payload,
						         work->pub_packet->payload_body.payload_len + 1);
						work->pub_packet->payload_body.payload = NULL;
						debug_msg("free memory payload");
					}

					if (tp_node != NULL) {
						nng_free(tp_node, sizeof(struct topic_and_node));
						tp_node = NULL;
						debug_msg("free memory topic_and_node");
					}
				}

				zfree(*topic_queue);
				zfree(topic_queue);
				break;

			case PUBACK:
				debug_msg("handling PUBACK");
				//TODO
				break;

			case PUBREC:
				debug_msg("handling PUBREC");
				pub_response.fixed_header.packet_type                 = PUBREL;
				pub_response.variable_header.pubrel.packet_identifier = work->pub_packet->variable_header.pubrec.packet_identifier;
				encode_pub_message(send_msg, &pub_response, work);
				tx_msgs(send_msg, work, self_pipe_id);
				//TODO
				break;

			case PUBREL:
				debug_msg("handling PUBREL");
				pub_response.fixed_header.packet_type                 = PUBCOMP;
				pub_response.variable_header.pubrel.packet_identifier = work->pub_packet->variable_header.pubrel.packet_identifier;
				encode_pub_message(send_msg, &pub_response, work);
				tx_msgs(send_msg, work, self_pipe_id);
				//TODO
				break;

			case PUBCOMP:
				debug_msg("handling PUBCOMP");
				//TODO
				break;

			default:
				break;
		}

	} else {
		debug_msg("decode message failed: %d", result);
		//TODO send DISCONNECT with reason_code if MQTT Version=5.0
		// tx_msgs
	}

	if (free_packet && work->pub_packet != NULL) {
		nng_free(work->pub_packet, sizeof(struct pub_packet_struct));
		work->pub_packet = NULL;
		debug_msg("free memory pub_packet");
	}
}

static uint32_t append_bytes_with_type(nng_msg *msg, uint8_t type, uint8_t *content, uint32_t len)
{
	if (len > 0) {
		nng_msg_append(msg, &type, 1);
		nng_msg_append_u16(msg, len);
		nng_msg_append(msg, content, len);
		return 0;
	}

	return 1;

}

bool encode_pub_message(nng_msg *dest_msg, struct pub_packet_struct *dest_pub_packet, const emq_work *work)
{
	uint8_t         tmp[4]     = {0};
	uint32_t        arr_len    = 0;
	int             append_res = 0;
	properties_type prop_type;

	const uint8_t proto_ver = conn_param_get_protover(work->cparam);
	nng_msg_clear(dest_msg);
	debug_msg("start encode message");

	//TODO nng_msg_set_cmd_type ?
	switch (dest_pub_packet->fixed_header.packet_type) {
		case PUBLISH:
			/*fixed header*/
			append_res = nng_msg_header_append(dest_msg, (uint8_t *) &dest_pub_packet->fixed_header, 1);

			arr_len    = put_var_integer(tmp, dest_pub_packet->fixed_header.remain_len);
			append_res = nng_msg_header_append(dest_msg, tmp, arr_len);

			/*variable header*/
			//topic name
			if (dest_pub_packet->variable_header.publish.topic_name.str_len > 0) {
				append_res = nng_msg_append_u16(dest_msg,
				                                dest_pub_packet->variable_header.publish.topic_name.str_len);

				append_res = nng_msg_append(dest_msg, dest_pub_packet->variable_header.publish.topic_name.str_body,
				                            dest_pub_packet->variable_header.publish.topic_name.str_len);
			}

			//identifier
			if (dest_pub_packet->fixed_header.qos > 0) {
				append_res = nng_msg_append_u16(dest_msg,
				                                dest_pub_packet->variable_header.publish.packet_identifier);
			}

#if SUPPORT_MQTT5_0
			if (PROTOCOL_VERSION_v5 == proto_ver) {
				//properties
				//properties length
				memset(tmp, 0, sizeof(tmp));
				arr_len = put_var_integer(tmp, dest_pub_packet->variable_header.publish.properties.len);
				nng_msg_append(dest_msg, tmp, arr_len);

				//Payload Format Indicator
				prop_type = PAYLOAD_FORMAT_INDICATOR;
				nng_msg_append(dest_msg, &prop_type, 1);
				nng_msg_append(dest_msg,
				               &dest_pub_packet->variable_header.publish.properties.content.publish.payload_fmt_indicator,
				               sizeof(dest_pub_packet->variable_header.publish.properties.content.publish.payload_fmt_indicator));

				//Message Expiry Interval
				prop_type = MESSAGE_EXPIRY_INTERVAL;
				nng_msg_append(dest_msg, &prop_type, 1);
				nng_msg_append_u32(dest_msg,
				                   dest_pub_packet->variable_header.publish.properties.content.publish.msg_expiry_interval.value);

				//Topic Alias
				if (dest_pub_packet->variable_header.publish.properties.content.publish.topic_alias.has_value) {
					prop_type = TOPIC_ALIAS;
					nng_msg_append(dest_msg, &prop_type, 1);
					nng_msg_append_u16(dest_msg,
					                   dest_pub_packet->variable_header.publish.properties.content.publish.topic_alias.value);
				}

				//Response Topic
				append_bytes_with_type(dest_msg, RESPONSE_TOPIC,
				                       (uint8_t *) dest_pub_packet->variable_header.publish.properties.content.publish.response_topic.str_body,
				                       dest_pub_packet->variable_header.publish.properties.content.publish.response_topic.str_len);

				//Correlation Data
				append_bytes_with_type(dest_msg, CORRELATION_DATA,
				                       dest_pub_packet->variable_header.publish.properties.content.publish.correlation_data.data,
				                       dest_pub_packet->variable_header.publish.properties.content.publish.correlation_data.data_len);

				//User Property
				append_bytes_with_type(dest_msg, USER_PROPERTY,
				                       (uint8_t *) dest_pub_packet->variable_header.publish.properties.content.publish.user_property.str_body,
				                       dest_pub_packet->variable_header.publish.properties.content.publish.user_property.str_len);

				//Subscription Identifier
				if (dest_pub_packet->variable_header.publish.properties.content.publish.subscription_identifier.has_value) {
					prop_type = SUBSCRIPTION_IDENTIFIER;
					nng_msg_append(dest_msg, &prop_type, 1);
					memset(tmp, 0, sizeof(tmp));
					arr_len = put_var_integer(tmp,
					                          dest_pub_packet->variable_header.publish.properties.content.publish.subscription_identifier.value);
					nng_msg_append(dest_msg, tmp, arr_len);
				}

				//CONTENT TYPE
				append_bytes_with_type(dest_msg, CONTENT_TYPE,
				                       (uint8_t *) dest_pub_packet->variable_header.publish.properties.content.publish.content_type.str_body,
				                       dest_pub_packet->variable_header.publish.properties.content.publish.content_type.str_len);
			}
#endif
			//payload
			if (dest_pub_packet->payload_body.payload_len > 0) {
				append_res = nng_msg_append(dest_msg, dest_pub_packet->payload_body.payload,
				                            dest_pub_packet->payload_body.payload_len);
			}
			break;

		case PUBREL:
		case PUBACK:
		case PUBREC:
		case PUBCOMP:
			/*fixed header*/
			nng_msg_header_append(dest_msg, (uint8_t *) &dest_pub_packet->fixed_header, 1);
			arr_len = put_var_integer(tmp, dest_pub_packet->fixed_header.remain_len);
			nng_msg_header_append(dest_msg, tmp, arr_len);

			/*variable header*/
			//identifier
			nng_msg_append_u16(dest_msg, dest_pub_packet->variable_header.pub_arrc.packet_identifier);

			//reason code
			if (dest_pub_packet->fixed_header.remain_len > 2) {
				uint8_t reason_code = dest_pub_packet->variable_header.pub_arrc.reason_code;
				nng_msg_append(dest_msg, (uint8_t *) &reason_code, sizeof(reason_code));

#if SUPPORT_MQTT5_0
				if (PROTOCOL_VERSION_v5 == proto_ver) {
					//properties
					if (dest_pub_packet->fixed_header.remain_len >= 4) {

						memset(tmp, 0, sizeof(tmp));
						arr_len = put_var_integer(tmp, dest_pub_packet->variable_header.pub_arrc.properties.len);
						nng_msg_append(dest_msg, tmp, arr_len);

						//reason string
						append_bytes_with_type(dest_msg, REASON_STRING,
						                       (uint8_t *) dest_pub_packet->variable_header.pub_arrc.properties.content.pub_arrc.reason_string.str_body,
						                       dest_pub_packet->variable_header.pub_arrc.properties.content.pub_arrc.reason_string.str_len);

						//user properties
						append_bytes_with_type(dest_msg, USER_PROPERTY,
						                       (uint8_t *) dest_pub_packet->variable_header.pub_arrc.properties.content.pub_arrc.user_property.str_body,
						                       dest_pub_packet->variable_header.pub_arrc.properties.content.pub_arrc.user_property.str_len);

					}
				}
#endif

			}
			break;

		default:
			break;
//		case RESERVED:
//			break;
//		case CONNECT:
//			break;
//		case CONNACK:
//			break;
//		case SUBSCRIBE:
//			break;
//		case SUBACK:
//			break;
//		case UNSUBSCRIBE:
//			break;
//		case UNSUBACK:
//			break;
//		case PINGREQ:
//			break;
//		case PINGRESP:
//			break;
//		case DISCONNECT:
//			break;
//		case AUTH:
//			break;
	}

	debug_msg("end encode message");
	return true;

}


reason_code decode_pub_message(emq_work *work)
{
	int     pos       = 0;
	int     used_pos  = 0;
	int     len;
	uint8_t proto_ver = conn_param_get_protover(work->cparam);

	nng_msg                  *msg        = work->msg;
	struct pub_packet_struct *pub_packet = work->pub_packet;

	uint8_t *msg_body = nng_msg_body(msg);
	size_t  msg_len   = nng_msg_len(msg);

	pub_packet->fixed_header            = *(struct fixed_header *) nng_msg_header(msg);
	pub_packet->fixed_header.remain_len = nng_msg_remaining_len(msg);

	debug_msg("cmd: %d, retain: %d, qos: %d, dup: %d, remaining length: %d",
	          pub_packet->fixed_header.packet_type,
	          pub_packet->fixed_header.retain,
	          pub_packet->fixed_header.qos,
	          pub_packet->fixed_header.dup,
	          pub_packet->fixed_header.remain_len);

	if (pub_packet->fixed_header.remain_len <= msg_len) {

		switch (pub_packet->fixed_header.packet_type) {
			case PUBLISH:
				//variable header
				//topic length
				NNI_GET16(msg_body + pos, pub_packet->variable_header.publish.topic_name.str_len);
				pub_packet->variable_header.publish.topic_name.str_body = (char *) nng_alloc(
						pub_packet->variable_header.publish.topic_name.str_len + 1);

				memset((char *) pub_packet->variable_header.publish.topic_name.str_body, '\0',
				       pub_packet->variable_header.publish.topic_name.str_len + 1);

				len = copy_utf8_str((uint8_t *) pub_packet->variable_header.publish.topic_name.str_body,
				                    msg_body + pos, &pos);

				if (pub_packet->variable_header.publish.topic_name.str_len > 0) {
					if (strchr(pub_packet->variable_header.publish.topic_name.str_body, '+') != NULL ||
					    strchr(pub_packet->variable_header.publish.topic_name.str_body, '#') != NULL) {

						//TODO search topic alias if mqtt version = 5.0

						//protocol error
						debug_msg("protocol error in topic:[%s], len: [%d]",
						          pub_packet->variable_header.publish.topic_name.str_body,
						          pub_packet->variable_header.publish.topic_name.str_len);

						return PROTOCOL_ERROR;
					}
				}

				debug_msg("topic: [%s]", pub_packet->variable_header.publish.topic_name.str_body);

				if (pub_packet->fixed_header.qos > 0) { //extract packet_identifier while qos > 0
					NNI_GET16(msg_body + pos, pub_packet->variable_header.publish.packet_identifier);
					pos += 2;
				}

				used_pos = pos;

#if SUPPORT_MQTT5_0
				if (PROTOCOL_VERSION_v5 == proto_ver) {

					pub_packet->variable_header.publish.properties.len = get_var_integer(msg_body, &pos);

					if (pub_packet->variable_header.publish.properties.len > 0) {
						for (uint32_t i = 0; i < pub_packet->variable_header.publish.properties.len;) {
							properties_type prop_type = get_var_integer(msg_body, &pos);
							//TODO the same property cannot appear twice
							switch (prop_type) {
								case PAYLOAD_FORMAT_INDICATOR:
									if (pub_packet->variable_header.publish.properties.content.publish.payload_fmt_indicator.has_value ==
									    false) {
										pub_packet->variable_header.publish.properties.content.publish.payload_fmt_indicator.value =
												*(msg_body + pos);
										pub_packet->variable_header.publish.properties.content.publish.payload_fmt_indicator.has_value = true;
										++pos;
										++i;
									} else {
										//Protocol Error
										return false;
									}
									break;

								case MESSAGE_EXPIRY_INTERVAL:
									if (pub_packet->variable_header.publish.properties.content.publish.msg_expiry_interval.has_value ==
									    false) {
										NNI_GET32(
												msg_body + pos,
												pub_packet->variable_header.publish.properties.content.publish.msg_expiry_interval.value);
										pub_packet->variable_header.publish.properties.content.publish.msg_expiry_interval.has_value = true;
										pos += 4;
										i += 4;
									} else {
										//Protocol Error
										return false;
									}
									break;

								case CONTENT_TYPE:
									if (pub_packet->variable_header.publish.properties.content.publish.content_type.str_len ==
									    0) {
										pub_packet->variable_header.publish.properties.content.publish.content_type.str_len =
												get_utf8_str(
														&pub_packet->variable_header.publish.properties.content.publish.content_type.str_body,
														msg_body,
														&pos);
										i = i +
										    pub_packet->variable_header.publish.properties.content.publish.content_type.str_len +
										    2;
									} else {
										//Protocol Error
										return false;
									}
									break;

								case TOPIC_ALIAS:
									if (pub_packet->variable_header.publish.properties.content.publish.topic_alias.has_value ==
									    false) {
										NNI_GET16(
												msg_body + pos,
												pub_packet->variable_header.publish.properties.content.publish.topic_alias.value);
										pub_packet->variable_header.publish.properties.content.publish.topic_alias.has_value = true;
										pos += 2;
										i += 2;
									} else {
										//Protocol Error
										return false;
									}
									break;

								case RESPONSE_TOPIC:
									if (pub_packet->variable_header.publish.properties.content.publish.response_topic.str_len ==
									    0) {
										pub_packet->variable_header.publish.properties.content.publish.response_topic.str_len
												= get_utf8_str(
												&pub_packet->variable_header.publish.properties.content.publish.response_topic.str_body,
												msg_body,
												&pos);
										i = i +
										    pub_packet->variable_header.publish.properties.content.publish.content_type.str_len +
										    2;
									} else {
										//Protocol Error
										return false;
									}

									break;

								case CORRELATION_DATA:
									if (pub_packet->variable_header.publish.properties.content.publish.correlation_data.data_len ==
									    0) {
										pub_packet->variable_header.publish.properties.content.publish.correlation_data.data_len
												= get_variable_binary(
												&pub_packet->variable_header.publish.properties.content.publish.correlation_data.data,
												msg_body + pos);
										pos += pub_packet->variable_header.publish.properties.content.publish.correlation_data.data_len +
										       2;
										i += pub_packet->variable_header.publish.properties.content.publish.correlation_data.data_len +
										     2;
									} else {
										//Protocol Error
										return false;
									}
									break;

								case USER_PROPERTY:
									if (pub_packet->variable_header.publish.properties.content.publish.response_topic.str_len ==
									    0) {
										pub_packet->variable_header.publish.properties.content.publish.response_topic.str_len =
												get_utf8_str(
														&pub_packet->variable_header.publish.properties.content.publish.user_property.str_body,
														msg_body,
														&pos);
										i += pub_packet->variable_header.publish.properties.content.publish.user_property.str_len +
										     2;
									} else {
										//Protocol Error
										return false;
									}
									break;

								case SUBSCRIPTION_IDENTIFIER:
									if (pub_packet->variable_header.publish.properties.content.publish.subscription_identifier.has_value ==
									    false) {
										used_pos = pos;
										pub_packet->variable_header.publish.properties.content.publish.subscription_identifier.value =
												get_var_integer(msg_body, &pos);
										i += (pos - used_pos);
										pub_packet->variable_header.publish.properties.content.publish.subscription_identifier.has_value = true;
										//Protocol error while Subscription Identifier = 0
										if (pub_packet->variable_header.publish.properties.content.publish.subscription_identifier.value ==
										    0) {
											return false;
										}
									} else {
										//Protocol Error
										return false;
									}
									break;

								default:
									i++;
									break;
							}
						}
					}
				}
#endif

				//payload
				pub_packet->payload_body.payload_len             = (uint32_t) (msg_len - (size_t) used_pos);

				if (pub_packet->payload_body.payload_len > 0) {
					pub_packet->payload_body.payload = (msg_body + pos);
					pub_packet->payload_body.payload = (uint8_t *) nng_alloc(
							pub_packet->payload_body.payload_len + 1);

					memset(pub_packet->payload_body.payload, 0, pub_packet->payload_body.payload_len + 1);

					memcpy(pub_packet->payload_body.payload, (uint8_t *) (msg_body + pos),
					       pub_packet->payload_body.payload_len);

					debug_msg("payload: [%s], len = %u", pub_packet->payload_body.payload,
					          pub_packet->payload_body.payload_len);
				}
				break;

			case PUBACK:
			case PUBREC:
			case PUBREL:
			case PUBCOMP:
				NNI_GET16(msg_body + pos, pub_packet->variable_header.pub_arrc.packet_identifier);
				pos += 2;
				if (pub_packet->fixed_header.remain_len == 2) {
					//Reason code can be ignored when remaining length = 2 and reason code = 0x00(Success)
					pub_packet->variable_header.pub_arrc.reason_code = SUCCESS;
					break;
				}
				pub_packet->variable_header.pub_arrc.reason_code = *(msg_body + pos);
				++pos;
#if SUPPORT_MQTT5_0
				if (pub_packet->fixed_header.remain_len > 4) {
					pub_packet->variable_header.pub_arrc.properties.len = get_var_integer(msg_body, &pos);
					for (uint32_t i = 0; i < pub_packet->variable_header.pub_arrc.properties.len;) {
						properties_type prop_type = get_var_integer(msg_body, &pos);
						switch (prop_type) {
							case REASON_STRING:
								pub_packet->variable_header.pub_arrc.properties.content.pub_arrc.reason_string.str_len = get_utf8_str(
										&pub_packet->variable_header.pub_arrc.properties.content.pub_arrc.reason_string.str_body,
										msg_body, &pos);
								i += pub_packet->variable_header.pub_arrc.properties.content.pub_arrc.reason_string.str_len +
								     2;
								break;

							case USER_PROPERTY:
								pub_packet->variable_header.pub_arrc.properties.content.pub_arrc.user_property.str_len = get_utf8_str(
										&pub_packet->variable_header.pub_arrc.properties.content.pub_arrc.user_property.str_body,
										msg_body, &pos);
								i += pub_packet->variable_header.pub_arrc.properties.content.pub_arrc.user_property.str_len +
								     2;
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

	return UNSPECIFIED_ERROR;
}

/**
 * byte array to hex string
 *
 * @param src
 * @param dest
 * @param src_len
 * @return
 */
static char *bytes_to_str(const unsigned char *src, char *dest, int src_len)
{
	int  i;
	char szTmp[3] = {0};

	for (i = 0; i < src_len; i++) {
		sprintf(szTmp, "%02X", (unsigned char) src[i]);
		memcpy(dest + i * 2, szTmp, 2);
	}
	return dest;
}

static void print_hex(const char *prefix, const unsigned char *src, int src_len)
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

#if 0
/**
 * pub handler
 *
 * @param arg: struct work pointer
 */
void pub_handler(void *arg, nng_msg *send_msg)
{
	emq_work *work = arg;

	work->pub_packet = (struct pub_packet_struct *) nng_alloc(sizeof(struct pub_packet_struct));

	struct topic_and_node    *res_node     = NULL;
	struct pub_packet_struct *pub_response = NULL;

	debug_msg("start decode msg");
	if (decode_pub_message(work)) {
		debug_msg("end decode msg");

		switch (work->pub_packet->fixed_header.packet_type) {
			case PUBLISH:
				debug_msg("handing msg cmd: [%d]", work->pub_packet->fixed_header.packet_type);
#if SUPPORT_MQTT5_0
				//process topic alias (For MQTT 5.0)
				//TODO get "TOPIC Alias Maximum" from CONNECT Packet Properties ,
				// topic_alias can't be larger than Topic Alias Maximum when the latter isn't equals 0;
				// Compare with TOPIC Alias Maximum;
				if (pub_packet->variable_header.publish.properties.content.publish.topic_alias.has_value) {

					if (pub_packet->variable_header.publish.properties.content.publish.topic_alias.value == 0) {
						//Protocol Error
						//TODO Send a DISCONNECT Packet with Reason Code "0x94" before close the connection (MQTT 5.0);
						return;
					}

					if (pub_packet->variable_header.publish.topic.str_len == 0) {
						//TODO
						// 1, query the entire Topic Name through Topic alias
						// 2, if query failed, Send a DISCONNECT Packet with Reason Code "0x82" before close the connection and return (MQTT 5.0);
						// 3, if query succeed, query node and data structure through Topic Name

					} else {
						topic = &pub_packet->variable_header.publish.topic;
						//TODO
						// 1, update Map value of Topic Alias
						// 2, query node and data structure through Topic Name
					}
				}
				//TODO save some useful publish message info and properties to global mqtt context while decode succeed
#endif

				//TODO add some logic if support MQTT3.1.1 & MQTT5.0
//				debug_msg("topic: %*.*s\n",
//				          work->pub_packet->variable_header.publish.topic_name.str_len,
//				          work->pub_packet->variable_header.publish.topic_name.str_len,
//				          work->pub_packet->variable_header.publish.topic_name.str_body);

				//do publish actions, eq: send payload to clients dependent on QoS ,topic alias if exists

				res_node = (struct topic_and_node *) nng_alloc(sizeof(struct topic_and_node));

				debug_msg("start search node! target topic: [%s]",
						  work->pub_packet->variable_header.publish.topic_name.str_body);
				search_node(work->db, &work->pub_packet->variable_header.publish.topic_name.str_body, res_node);
//				debug_msg(
//						"end search node! topic: [%s], node.topic: [%s], node.state: [%d], node.down: [%p], node.next: [%p]",
//						*res_node->topic == NULL ? "NULL": *res_node->topic,
//						res_node->node->topic,
//						res_node->node->state,
//						res_node->node->down,
//						res_node->node->next);
#if 0
				if (work->pub_packet->fixed_header.retain == 1) {
					//store this message to the topic node
					res_node->node->retain  = true;
					res_node->node->len     = work->pub_packet->payload_body.payload_len;
					res_node->node->message = nng_alloc(res_node->node->len);

					memcpy((uint8_t *) res_node->node->message, work->pub_packet->payload_body.payload,
						   res_node->node->len);//according to node.len, free memory before delete this node

					if (res_node->node->state == UNEQUAL) {
						//TODO add node but client_id is unnecessary;
					}

				} else {
					if (res_node->node->state == UNEQUAL) {
						//topic not found,
						zfree(res_node);
						work->msg   = NULL;
						work->state = RECV;
						nng_ctx_recv(work->ctx, work->aio);
						return;
					}
				}
#endif
				//TODO compare Publish QoS with Subscribe OoS, decide by the maximum;
				switch (work->pub_packet->fixed_header.qos) {
					case 0:
						//publish only once
						work->pub_packet->fixed_header.dup = 0;
						debug_msg("preparing for publish message to clients who subscribed topic [%s]",
								  work->pub_packet->variable_header.publish.topic_name.str_body);

						forward_msg(work->db->root, res_node,
									work->pub_packet->variable_header.publish.topic_name.str_body, send_msg,
									work->pub_packet, work);

						break;

					case 1:
						pub_response = (struct pub_packet_struct *) nng_alloc(sizeof(struct pub_packet_struct));
						pub_response->fixed_header.packet_type = PUBACK;
						pub_response->fixed_header.dup         = 0;
						pub_response->fixed_header.qos         = 0;
						pub_response->fixed_header.retain      = 0;
						pub_response->fixed_header.remain_len  = 2;

						pub_response->variable_header.puback.packet_identifier =
								work->pub_packet->variable_header.publish.packet_identifier;

						encode_pub_message(send_msg, pub_response);

						//response PUBACK to client

						work->state = SEND;
						work->msg   = send_msg;
						nng_aio_set_msg(work->aio, work->msg);
						work->msg = NULL;
						//nng_aio_set_pipeline(work->aio, work->pid.id);
						nng_ctx_send(work->ctx, work->aio);

						nng_free(pub_response, sizeof(struct pub_packet_struct));

						work->pub_packet->fixed_header.dup = 0;
						forward_msg(work->db->root, res_node,
									work->pub_packet->variable_header.publish.topic_name.str_body, send_msg,
									work->pub_packet, work);

						break;

					case 2:
						break;

					default:
						//Error Qos
						work->msg   = NULL;
						work->state = RECV;
						nng_ctx_recv(work->ctx, work->aio);
						break;
				}

				break;

			case PUBACK:
				break;

			case PUBREL:
				break;

			case PUBREC:
				break;
			case PUBCOMP:
				break;

			default:
				break;
		}
		if (res_node != NULL) {
			nng_free(res_node, sizeof(struct topic_and_node));
			res_node = NULL;
		}

	}
}

#endif