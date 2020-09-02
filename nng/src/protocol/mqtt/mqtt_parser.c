/***
 * Jaylin
 * EMQ
 * 
 * 
 * 
 * 
 * MIT 
 *
 **/

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
	if (len < 0 || len > 65536) return ERR_INVAL;

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

	uint32_t	len, tmp, pos = 0;
	int32_t		rv = 0;

	if (packet[pos] != CMD_CONNECT) {
		rv = -1;
		return rv;
	} else {
		pos++;
	}
	//remaining length
	len = get_var_integer(packet, &pos);
	//protocol name
	rv = copy_utf8_str(cparam->pro_name, packet, &pos);
	debug_msg("pro_name: %s", cparam->pro_name);
	//protocol ver
	cparam->pro_ver = packet[pos];
	pos ++;
	//connect flag
	cparam->con_flag = packet[pos];
	cparam->clean_start = cparam->con_flag & 0x02;
	cparam->will_flag   = cparam->con_flag & 0x04;
	cparam->will_qos    = cparam->con_flag & 0x18;
	cparam->will_retain = cparam->con_flag & 0x20;
	debug_msg("conn flag:%x", cparam->con_flag);
	pos ++;
	//keepalive
	NNI_GET16(packet + pos, tmp);
	cparam->keepalive_mqtt = tmp;
	pos+=2;
	//properties
	if (cparam->pro_ver == 5) {
		//TODO
		debug_msg("MQTT 5 Properties");
	}
	//payload client_id
	rv =rv|copy_utf8_str(cparam->clientid, packet, &pos);
	debug_msg("clientid: %s %d", cparam->clientid, rv);
	//will properties
	if (cparam->pro_ver == 5) {
		debug_msg("MQTT 5 Will Properties");
	}
	//will topic
	if(cparam->will_flag != 0) {
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
