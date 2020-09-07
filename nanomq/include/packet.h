// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//
//
// The Struct to store mqtt_packet. 

#ifndef MQTT_PACKET_H
#define MQTT_PACKET_H

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

struct mqtt_string {
	char *  str_body;
	int     len;
};
typedef struct mqtt_string mqtt_string;

struct mqtt_string_node {
	struct mqtt_string_node *  next;
	mqtt_string *       it;
};
typedef struct mqtt_string_node mqtt_string_node;

struct mqtt_binary {
	unsigned char * str_body;
	int             len;
};
typedef struct mqtt_binary mqtt_binary;

struct mqtt_str_pair {
	char *	str_key; // key
	int 	len_key;
	char *	str_value; // value
	int 	len_value;
};
typedef struct mqtt_str_pair mqtt_str_pair;

union Property_type{
	uint8_t u8;
	uint16_t u16;
	uint32_t u32;
	uint32_t varint;
	mqtt_binary binary;
	mqtt_string str;
	mqtt_str_pair strpair;
};

struct property {
	uint8_t 			id;
	union Property_type	value;
	struct property * 	next;
};
typedef struct property property;

struct mqtt_property {
	uint32_t            len;
	uint32_t			count;
	struct property *   property;
	struct property *	property_end;
};
typedef struct mqtt_property mqtt_property;

//variable header in mqtt_packet_subscribe
struct topic_with_option {
	uint8_t         qos: 2;
	uint8_t         no_local: 1;
	uint8_t         retain_as_publish: 1;
	uint8_t         retain_handling: 4; // !!!!!TODO actually 2 bits
	mqtt_string     topic_filter;
	uint8_t         reason_code;
};
typedef struct topic_with_option topic_with_option;

struct topic_node {
	topic_with_option * it;
	struct topic_node * next;
};
typedef struct topic_node topic_node;

struct packet_subscribe {
	uint16_t packet_id;
	union Property_type sub_id;
	union Property_type user_property;
	topic_node * node; // storage topic_with_option
};
typedef struct packet_subscribe packet_subscribe;

struct packet_unsubscribe {
	uint16_t packet_id;
	union Property_type user_property;
	topic_node * node; // storage topic_with_option
};
typedef struct packet_unsubscribe packet_unsubscribe;

#endif

