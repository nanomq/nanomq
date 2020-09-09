/**
  * Created by Alvin on 2020/7/25.
  */

#ifndef NANOMQ_PUB_HANDLER_H
#define NANOMQ_PUB_HANDLER_H

#include <nng/nng.h>
#include <apps/broker.h>
#include "nng/protocol/mqtt/mqtt.h"

typedef uint32_t variable_integer;

struct variable_string {
	uint32_t str_len;
	char     *str_body;
};

struct variable_binary {
	uint32_t data_len;
	uint8_t  *data;
};

//MQTT Fixed header
struct fixed_header {
	//flag_bits
	uint8_t                   retain: 1;
	uint8_t                   qos: 2;
	uint8_t                   dup: 1;
	//packet_types
	mqtt_control_packet_types packet_type: 4;
	//remaining length
	uint32_t                  remain_len;
};

struct property_u8 {
	bool    has_value; //false: no value;
	uint8_t value;
};

struct property_u16 {
	bool     has_value; //false: no value;
	uint16_t value;
};

struct property_u32 {
	bool     has_value; //false: no value;
	uint32_t value;
};


//Special for publish message data structure
union property_content {
	struct {
		struct property_u8     payload_fmt_indicator;
		struct property_u32    msg_expiry_interval;
		struct property_u16    topic_alias;
		struct variable_string response_topic;
		struct variable_binary correlation_data;
		struct variable_string user_property;
		struct property_u32    subscription_identifier;
		struct variable_string content_type;
	} publish;
	struct {
		struct variable_string reason_string;
		struct variable_string user_property;
	} pub_arrc, puback, pubrec, pubrel, pubcomp;
};

//Properties
struct properties {
	uint32_t               len; //property length, exclude itself,variable byte integer;
	union property_content content;
};

//MQTT Variable header
union variable_header {
	struct {
		uint16_t               packet_identifier;
		struct variable_string topic_name;
		struct properties      properties;
	} publish;

	struct {
		uint16_t          packet_identifier;
		reason_code       reason_code: 8;
		struct properties properties;
	} pub_arrc, puback, pubrec, pubrel, pubcomp;
};


struct mqtt_payload {
	uint8_t  *payload;
	uint32_t payload_len;
};

struct pub_packet_struct {
	struct fixed_header   fixed_header;
	union variable_header variable_header;
	struct mqtt_payload   payload_body;
};

struct pipe_info {
	uint8_t                   qos;
	mqtt_control_packet_types cmd;

	uint32_t pipe;
	uint32_t index;
	emq_work *pub_work;
};

struct pipe_content {
	uint32_t total;
	uint32_t current_index;
	bool (*encode_msg)(nng_msg *, const emq_work *, mqtt_control_packet_types, uint8_t, bool);
	struct pipe_info *pipe_info;
};

typedef void (*handle_client)(struct client *sub_client, emq_work *pub_work, struct pipe_content *pipe_ct);

bool
encode_pub_message(nng_msg *dest_msg, const emq_work *work, mqtt_control_packet_types cmd, uint8_t sub_qos, bool dup);
reason_code decode_pub_message(emq_work *work);
void
foreach_client(struct clients *sub_clients, emq_work *pub_work, struct pipe_content *pipe_ct, handle_client handle_cb);
void free_pub_packet(struct pub_packet_struct *pub_packet);
void free_pipes_info(struct pipe_info *p_info);
void init_pipe_content(struct pipe_content *pipe_ct);
void handle_pub(emq_work *work, struct pipe_content *pipe_ct);


#endif //NNG_PUB_HANDLER_H
