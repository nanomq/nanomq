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
#include "core/nng_impl.h"
#include "nng/protocol/mqtt/mqtt_parser.h"
#include "nng/protocol/mqtt/mqtt.h"
#include "include/nng_debug.h"

static uint8_t get_value_size(uint64_t value);
static uint64_t power(uint64_t x, uint32_t n);

static uint64_t power(uint64_t x, uint32_t n)
{
	uint64_t val = 1;

	for (uint32_t i = 0; i <= n; ++i) {
		val = x * val;
	}

	return val / x;
}

/**
 * get size from value
 *
 * @param value
 * @return
 */
static uint8_t get_value_size(uint64_t value)
{
	uint8_t  len = 1;
	uint64_t pow;
	for (int i   = 1; i <= 4; ++i) {
		pow = power(0x100, i);
		if (value >= pow) {
			++len;
		} else {
			break;
		}
	}
	return len;
}

/**
 * put a value to variable byte array
 * @param dest
 * @param value
 * @return data length
 */
uint8_t put_var_integer(uint8_t *dest, uint32_t value)
{
	uint8_t  len        = 0;
	uint32_t init_val   = 0x7F;
	uint8_t  value_size = get_value_size(value);

	for (uint32_t i = 0; i < value_size; ++i) {

		if (i > 0) {
			init_val = (init_val * 0x80) | 0xFF;
		}
		dest[i] = value / (uint32_t) power(0x80, i);
		if (value > init_val) {
			dest[i] |= 0x80;
		}
		len++;
	}
	return len;
}

/**
 * Get variable integer value
 *
 * @param buf Byte array
 * @param pos
 * @return Integer value
 */
uint32_t get_var_integer(const uint8_t *buf, int *pos)
{
	uint8_t  temp;
	uint32_t result = 0;

	int p = *pos;
	int i = 0;

	do {
		temp   = *(buf + p);
		result = result + (uint32_t) (temp & 0x7f) * (power(0x80, i));
		p++;
	}
	while ((temp & 0x80) > 0 && i++ < 4);
	*pos = p;
	return result;
}

/**
 * Get utf-8 string
 *
 * @param dest output string
 * @param src input bytes
 * @param pos
 * @return string length -1: not utf-8, 0: empty string, >0 : normal utf-8 string
 */
int32_t get_utf8_str(char **dest, const uint8_t *src, int *pos)
{
	int32_t str_len = 0;
	NNI_GET16(src + (*pos), str_len);

	*pos = (*pos) + 2;
	if (str_len > 0) {
		if (utf8_check((const char *) (src + *pos), str_len) == ERR_SUCCESS) {
			*dest = (char *) (src + (*pos));
			*pos = (*pos) + str_len;
		} else {
			str_len = -1;
		}
	}
	return str_len;
}

/**
 * copy utf-8 string to dst
 *
 * @param dest output string
 * @param src input bytes
 * @param pos
 * @return string length -1: not utf-8, 0: empty string, >0 : normal utf-8 string
 */
int32_t copy_utf8_str(uint8_t *dest, const uint8_t *src, int *pos)
{
	int32_t str_len = 0;

	NNI_GET16(src + (*pos), str_len);

	*pos = (*pos) + 2;
	if (str_len > 0) {
		if (utf8_check((const char *) (src + *pos), str_len) == ERR_SUCCESS) {
			memcpy(dest, src + (*pos), str_len);
			*pos = (*pos) + str_len;
		} else {
			str_len = -1;
		}
	}
	return str_len;
}

int utf8_check(const char *str, size_t len)
{
	int i;
	int j;
	int codelen;
	int codepoint;

	const unsigned char *ustr = (const unsigned char *) str;

	if (!str) return ERR_INVAL;
	if (len > 65536) return ERR_INVAL;

	for (i = 0; i < len; i++) {
		if (ustr[i] == 0) {
			return ERR_MALFORMED_UTF8;
		} else if (ustr[i] <= 0x7f) {
			codelen   = 1;
			codepoint = ustr[i];
		} else if ((ustr[i] & 0xE0) == 0xC0) {
			/* 110xxxxx - 2 byte sequence */
			if (ustr[i] == 0xC0 || ustr[i] == 0xC1) {
				/* Invalid bytes */
				return ERR_MALFORMED_UTF8;
			}
			codelen   = 2;
			codepoint = (ustr[i] & 0x1F);
		} else if ((ustr[i] & 0xF0) == 0xE0) {
			/* 1110xxxx - 3 byte sequence */
			codelen   = 3;
			codepoint = (ustr[i] & 0x0F);
		} else if ((ustr[i] & 0xF8) == 0xF0) {
			/* 11110xxx - 4 byte sequence */
			if (ustr[i] > 0xF4) {
				/* Invalid, this would produce values > 0x10FFFF. */
				return ERR_MALFORMED_UTF8;
			}
			codelen   = 4;
			codepoint = (ustr[i] & 0x07);
		} else {
			/* Unexpected continuation byte. */
			return ERR_MALFORMED_UTF8;
		}

		/* Reconstruct full code point */
		if (i == len - codelen + 1) {
			/* Not enough data */
			return ERR_MALFORMED_UTF8;
		}
		for (j = 0; j < codelen - 1; j++) {
			if ((ustr[++i] & 0xC0) != 0x80) {
				/* Not a continuation byte */
				return ERR_MALFORMED_UTF8;
			}
			codepoint = (codepoint << 6) | (ustr[i] & 0x3F);
		}

		/* Check for UTF-16 high/low surrogates */
		if (codepoint >= 0xD800 && codepoint <= 0xDFFF) {
			return ERR_MALFORMED_UTF8;
		}

		/* Check for overlong or out of range encodings */
		/* Checking codelen == 2 isn't necessary here, because it is already
		 * covered above in the C0 and C1 checks.
		 * if(codelen == 2 && codepoint < 0x0080){
		 *	 return ERR_MALFORMED_UTF8;
		 * }else
		*/
		if (codelen == 3 && codepoint < 0x0800) {
			return ERR_MALFORMED_UTF8;
		} else if (codelen == 4 && (codepoint < 0x10000 || codepoint > 0x10FFFF)) {
			return ERR_MALFORMED_UTF8;
		}

		/* Check for non-characters */
		if (codepoint >= 0xFDD0 && codepoint <= 0xFDEF) {
			return ERR_MALFORMED_UTF8;
		}
		if ((codepoint & 0xFFFF) == 0xFFFE || (codepoint & 0xFFFF) == 0xFFFF) {
			return ERR_MALFORMED_UTF8;
		}
		/* Check for control characters */
		if (codepoint <= 0x001F || (codepoint >= 0x007F && codepoint <= 0x009F)) {
			return ERR_MALFORMED_UTF8;
		}
	}
	return ERR_SUCCESS;
}

uint16_t get_variable_binary(uint8_t **dest, const uint8_t *src)
{
	uint16_t len = 0;
	NNI_GET16(src, len);
	*dest = (uint8_t *) (src + 2);
	return len;
}

int fixed_header_adaptor(uint8_t *packet, nng_msg *dst)
{
	nni_msg  *m;
	int      rv, pos = 1;
	uint32_t len;

	m   = (nni_msg *)dst;
	len = get_var_integer(packet, &pos);

	rv = nni_msg_header_append(m, packet, pos);
	return rv;
}

int variable_header_adaptor(uint8_t *packet, nni_msg *dst)
{
	nni_msg  *m;
	int      pos = 0;
	uint32_t len;

	return 0;
}


static char *client_id_gen(int *idlen, const char *auto_id_prefix, int auto_id_prefix_len)
{
	char *client_id;

	return client_id;
}

/**
 * TODO length limitation
 * 
 */
int32_t conn_handler(uint8_t *packet, conn_param *cparam)
{

	uint32_t	len, tmp, pos = 0, len_of_properties = 0;
	int         len_of_str = 0;
	int32_t		rv = 0;
	uint8_t     property_id;

	if (packet[pos] != CMD_CONNECT) {
		rv = -1;
		return rv;
	} else {
		pos++;
	}
	//remaining length
	len = (uint32_t)get_var_integer(packet, &pos);
	//protocol name
	rv = (uint32_t)copy_utf8_str(cparam->pro_name, packet, &pos);
	debug_msg("pro_name: %s", cparam->pro_name);
	//protocol ver
	cparam->pro_ver = packet[pos];
	pos ++;
	//connect flag
	cparam->con_flag = packet[pos];
	cparam->clean_start = (cparam->con_flag & 0x02) >> 1;
	cparam->will_flag   = (cparam->con_flag & 0x04) >> 2;
	cparam->will_qos    = (cparam->con_flag & 0x18) >> 3;
	cparam->will_retain = (cparam->con_flag & 0x20) >> 5;
	debug_msg("conn flag:%x", cparam->con_flag);
	pos ++;
	//keepalive
	NNI_GET16(packet + pos, tmp);
	cparam->keepalive_mqtt = tmp;
	pos+=2;
	//properties
	if (cparam->pro_ver == PROTOCOL_VERSION_v5) {
		debug_msg("MQTT 5 Properties");
		len_of_properties = (uint32_t)get_var_integer(packet, &pos);
		uint32_t target_pos = pos + len_of_properties;
		debug_msg("propertyLen in variable [%d]", len_of_properties);

		// parse property in variable header
		if (len_of_properties > 0) {
			while (1) {
				property_id = packet[pos++];
				switch (property_id) {
					case SESSION_EXPIRY_INTERVAL:
						debug_msg("SESSION_EXPIRY_INTERVAL");
						NNI_GET32(packet+pos, cparam->session_expiry_interval);
						pos += 4;
						break;
					case RECEIVE_MAXIMUM:
						debug_msg("RECEIVE_MAXIMUM");
						NNI_GET16(packet+pos, cparam->rx_max);
						pos += 2;
						break;
					case MAXIMUM_PACKET_SIZE:
						debug_msg("MAXIMUM_PACKET_SIZE");
						NNI_GET32(packet+pos, cparam->max_packet_size);
						pos += 4;
						break;
					case TOPIC_ALIAS_MAXIMUM:
						debug_msg("TOPIC_ALIAS_MAXIMUM");
						NNI_GET16(packet+pos, cparam->topic_alias_max);
						pos += 2;
						break;
					case REQUEST_RESPONSE_INFORMATION:
						debug_msg("REQUEST_RESPONSE_INFORMATION");
						cparam->req_resp_info = packet[pos++];
						break;
					case REQUEST_PROBLEM_INFORMATION:
						debug_msg("REQUEST_PROBLEM_INFORMATION");
						cparam->req_problem_info = packet[pos++];
						break;
					case USER_PROPERTY:
						debug_msg("USER_PROPERTY");
						// key
						copy_utf8_str(cparam->user_property.key, packet, &len_of_str);
						pos += (uint32_t)len_of_str;
						cparam->user_property.len_key = len_of_str;
						len_of_str = 0;
						// value
						copy_utf8_str(cparam->user_property.val, packet, &len_of_str);
						pos += (uint32_t)len_of_str;
						cparam->user_property.len_val = len_of_str;
						len_of_str = 0;
						break;
					case AUTHENTICATION_METHOD:
						debug_msg("AUTHENTICATION_METHOD");
						copy_utf8_str(cparam->auth_method.body, packet, &len_of_str);
						pos += (uint32_t)len_of_str;
						cparam->auth_method.len = len_of_str;
						len_of_str = 0;
						break;
					case AUTHENTICATION_DATA:
						debug_msg("AUTHENTICATION_DATA");
						copy_utf8_str(cparam->auth_data.body, packet, &len_of_str);
						pos += (uint32_t)len_of_str;
						cparam->auth_data.len = len_of_str;
						len_of_str = 0;
						break;
					default:
						break;
				}
				if (pos == target_pos) {
					break;
				} else if (pos > target_pos) {
					debug_msg("ERROR: protocol error");
					return PROTOCOL_ERROR;
				}
			}
		}
	}
	debug_msg("pos after property: [%d]", pos);
	//payload client_id
	len_of_str = copy_utf8_str(cparam->clientid, packet, &pos);
	debug_msg("clientid: [%s] [%d]", cparam->clientid, len_of_str);
	len_of_str = 0;
	//will topic
	if (cparam->will_flag != 0) {
		if (cparam->pro_ver == PROTOCOL_VERSION_v5) {
			len_of_properties = get_var_integer(packet, &pos);
			uint32_t target_pos = pos + len_of_properties;
			debug_msg("propertyLen in payload [%d]", len_of_properties);

			// parse property in variable header
			if (len_of_properties > 0) {
				while (1) {
					property_id = packet[pos++];
					switch (property_id) {
						case WILL_DELAY_INTERVAL:
							debug_msg("WILL_DELAY_INTERVAL");
							NNI_GET32(packet+pos, cparam->will_delay_interval);
							pos += 4;
							break;
						case PAYLOAD_FORMAT_INDICATOR:
							debug_msg("PAYLOAD_FORMAT_INDICATOR");
							cparam->payload_format_indicator = packet[pos++];
							break;
						case MESSAGE_EXPIRY_INTERVAL:
							debug_msg("MESSAGE_EXPIRY_INTERVAL");
							NNI_GET32(packet+pos, cparam->msg_expiry_interval);
							pos += 4;
							break;
						case CONTENT_TYPE:
							debug_msg("CONTENT_TYPE");
							rv = rv|copy_utf8_str(cparam->content_type.body, packet, &len_of_str);
							pos += (uint32_t)len_of_str;
							len_of_str = 0;
							debug_msg("content type: %s %d", cparam->content_type.body, rv);
							break;
						case RESPONSE_TOPIC:
							debug_msg("RESPONSE_TOPIC");
							rv = rv|copy_utf8_str(cparam->resp_topic.body, packet, &len_of_str);
							pos += (uint32_t)len_of_str;
							cparam->resp_topic.len = len_of_str;
							len_of_str = 0;
							debug_msg("resp topic: %s %d", cparam->resp_topic.body, rv);
							break;
						case CORRELATION_DATA:
							debug_msg("CORRELATION_DATA");
							rv = rv|copy_utf8_str(cparam->corr_data.body, packet, &len_of_str);
							pos += (uint32_t)len_of_str;
							cparam->corr_data.len = len_of_str;
							len_of_str = 0;
							debug_msg("corr_data: %s %d", cparam->corr_data.body, rv);
							break;
						case USER_PROPERTY:
							debug_msg("USER_PROPERTY");
							// key
							copy_utf8_str(cparam->payload_user_property.key, packet, &len_of_str);
							pos += (uint32_t)len_of_str;
							cparam->payload_user_property.len_key = len_of_str;
							len_of_str = 0;
							// value
							copy_utf8_str(cparam->payload_user_property.val, packet, &len_of_str);
							pos += (uint32_t)len_of_str;
							cparam->payload_user_property.len_val = len_of_str;
							len_of_str = 0;
							break;
						default:
							break;
					}
					if (pos == target_pos) {
						break;
					}else if (pos > target_pos) {
						debug_msg("ERROR: protocol error");
						return PROTOCOL_ERROR;
					}
				}
			}
		}
		rv =rv|copy_utf8_str(cparam->will_topic, packet, &pos);
		debug_msg("will_topic: %s %d", cparam->will_topic, rv);
		//will msg
		rv =rv|copy_utf8_str(cparam->will_msg, packet, &pos);
		debug_msg("will_msg: %s %d", cparam->will_msg, rv);
	}
	//username
	if ((cparam->con_flag & 0x80) > 0) {
		rv =rv|copy_utf8_str(cparam->username, packet, &pos);
		debug_msg("username: %s %d %d", cparam->username, rv, 3 & 4);
	}
	//password
	if ((cparam->con_flag & 0x40) > 0) {
		rv =rv|copy_utf8_str(cparam->password, packet, &pos);
		debug_msg("password: %s %d", cparam->password, rv);
	}
	//what if rv = 0?
	return rv;
}
